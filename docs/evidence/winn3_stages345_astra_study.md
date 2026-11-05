# Winn Protocol v3 Stages 3, 4, 5 Systems Engineering Study: Astra

- **Model**: `gpt-6-astra` (extra high reasoning)
- **Completed**: 2026-09-14 08:29:15 UTC
- **Exit code**: 0
- **Wall clock limit**: 21600s (timed out: False)

## Deep Study Report & Implementation Plan

# Winn Protocol v3: Stages 3, 4, and 5 implementation study

Astra. Prepared 2026-09-14 08:28 UTC. Workspace: `/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra`.

## Decision and scope

The study includes implemented candidate code, complete exact diffs for 56 files, adversarial verification suites, and measured results. **The candidate passes the final local Winn race suite and the supported native/compiler checks listed below. It is not a declaration that the physical-device 200+ Mbps ceiling has been removed.** No WAN or physical VPN throughput test ran. No cloud deployment, signing, push, remote state, or release publication occurred.

| Stage | Implemented candidate | Verified boundary | Remaining acceptance |
| --- | --- | --- | --- |
| 3 | Optional BatchCarrier, generation-bound cancellation, Linux/Android mmsg, Linux GSO/GRO, Darwin ready-drain, loop integration | Darwin race tests; 174 Linux arm64 carrier tests with no skips; crosscompile matrix | Real Android kernel/device; NIC/WAN behavior; production gateway socket batching and explicit offload enablement |
| 4 Apple | Plural C ABI, array enqueue/dequeue, production Swift pump, retained exports | Strict cgo/race tests, three Swift harness modes, 338 host-contract checks, local dead-strip symbol probe | Signed iOS/macOS slices, installed packet tunnel and physical traffic |
| 4 Android | Bounded reusable packet ring, batched WNN3 frames, actual LocalSocket adapter wiring | 136 JVM tests including production-source compilation and v2 compatibility | Required release APK and phone smoke; actual TUN/LocalSocket syscall, power, and throughput measurements |
| 4 Windows | Runnable `--in-process-candidate` with direct Wintun device and real Winn runtime | Portable race tests, authenticated UDP/direct-device fixture, Windows amd64/arm64 builds | The existing supervisor does not select it. Service control, signed profile provenance, routes, DLL/device and packaging acceptance remain |
| 5 | Ordered parallel AEAD, sequential nonce/replay accounting, epoch barriers, batch loop use and worker retirement | Full race suite, deterministic adverse scheduling and replay/rekey tests, allocation assertions, CPU/batch benchmark matrix | Adaptive worker policy, many-session resource budget and physical end-to-end performance |

Use these candidates as reviewable implementation bytes. Retain production acceptance gates until the missing target evidence exists. This report does not apply an OWNER-DECISIONS-NEEDED label, alter a ruling, or authorize deployment.

## Provenance and corrected baseline

This workspace is a file copy. Its `.git` directory has HEAD/config/index but lacks the repository objects and references required by Git. `git status` fails. There is no verified HEAD SHA to attach to this candidate. The implementation is instead scoped to the original file bytes in [baseline_manifest.json](stages345_astra/baseline_manifest.json) and the final changed-file hashes in [candidate_manifest.json](stages345_astra/candidate_manifest.json). The original snapshot is `/tmp/winn3-stages345-astra-baseline`.

The root Go executable reports 1.26.5; the existing module directive automatically selected **Go 1.27.0** for this work. The protocol module still pins x/net v0.56.0, x/sys v0.47.0, and x/crypto v0.54.0. Its go.mod/go.sum did not change. The nested Windows module now links the local protocol module, requires Go 1.27.0, and resolves the protocol module's existing transitive versions. Wintun remains pinned at 0fa3db229ce2.

The initial full race command failed in redteam because the copy lacked its generated verdict fixture and child builds could not stamp invalid Git metadata. Core, carrier, session, driver, gateway and TUN passed that initial run. Generating the existing transcript fixture and using `GOFLAGS=-buildvcs=false` restored the actual test environment. These are disclosed build-environment repairs, not test skips. The final full race command passes.

The mission's historical 78 ns and 532.86 MB/s measurements are plausible historical samples, but their boundaries need qualification. The cached-demux benchmark invokes the PRF; it is not a complete replay verification benchmark. The transport benchmark executes a core SealInto/OpenInto round trip; it contains no session enqueue, host bridge, socket or TUN. OpenAtInto does exist in core/index.go. Independent baseline probes observed about 85 ns for cached PRF, zero core allocations, and five allocations per packet across Enqueue -> PollInto -> scalar Deliver. The full scalar datapath was therefore not established as allocation-free. Sources: [winn_protocol_experimental/winn3/core/wire_speed_candidate_test.go:95](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/wire_speed_candidate_test.go:95), [winn_protocol_experimental/winn3/core/wire_speed_candidate_test.go:119](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/wire_speed_candidate_test.go:119), [winn_protocol_experimental/winn3/core/index.go:170](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/index.go:170).

Baseline 1200-byte core samples in this run were 496.20 to 508.57 MB/s, with 0 B/op and 0 allocs/op. Concurrent lanes were active, so these are boundary checks, not a controlled comparison against the historical number. Evidence: [baseline_crypto_benchmark.txt](stages345_astra/baseline_crypto_benchmark.txt), [review.md](stages345_astra/review.md).

The supplied 200+ Mbps physical result is mission context, not remeasured evidence here. 200 Mbps is 25 decimal MB/s. A roughly 500 MB/s core round trip is not a prediction of app goodput: queueing, wakeups, device policy, memory copies, packet size, packet loss and the gateway's own path all remain in the system.

## System architecture and ownership

```mermaid
flowchart LR
  H[Host packet source] --> B[Native batch or direct device]
  B --> T[TUN validation and gate]
  T --> Q[Session data queue]
  Q --> R[Ordered reservation]
  R --> W[Bounded AEAD workers]
  W --> O[Ordered completed datagrams]
  O --> C[Carrier batch]
  C --> U[Outer UDP socket]
  U --> V[Complete received datagrams]
  V --> S[Speculative AEAD workers]
  S --> A[Ordered authentication and replay commit]
  A --> G[Control boundary and gate projection]
  G --> B
```

Buffers have a single explicit owner at each boundary. Socket descriptors belong to the carrier or its documented lender. Transmit buffers remain live until SendBatch returns. A committed prefix cannot be sent again. Native C pointers live only inside a foreign call. Wintun buffers are released only after copying. Receive packet views borrow scratch until the loop synchronously writes them into the TUN layer, then the loop clears scratch and views.

A control boundary is a sequencing boundary, not a reason to hold a host gate while waiting for crypto. Calling gate.Set under the session mutex can deadlock against a TUN outbound operation holding the gate while entering Enqueue. The receive API returns a completed DATA/PAD prefix before a control record. The loop projects the gate outside the session mutex, consumes the prefix, and then handles the next control alone. DATA,CLOSE,DATA is explicitly tested.

## Stage 3: carrier and socket generation

### Exact API and platform behavior

[winn_protocol_experimental/winn3/carrier/batch.go:29](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch.go:29) and [winn_protocol_experimental/winn3/carrier/batch.go:44](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch.go:44) define:

```go
type BatchMsg struct {
    Buffers     [][]byte
    Addr        netip.AddrPort
    Flags       int
    N           int
    SegmentSize int
    Segments    int
}

type BatchCarrier interface {
    RecvBatch(context.Context, []BatchMsg) (int, error)
    SendBatch(context.Context, []BatchMsg) (int, error)
}

type LifetimeBinder interface {
    BindLifetime(context.Context) error
}
```

These declarations are excerpts of the complete package diffs in the appendix. Batch size is at most 32; each datagram has at most 16 scatter/gather slices. Buffers within one descriptor form one Winn datagram. They are never separate records. `N` is the per-record byte count. Receive address, flags and GRO provenance are outputs; callers cannot inject syscall flags or segmentation metadata on send. Zero destination chooses the configured peer; another destination is rejected. Empty batches return zero successfully. For a nonempty batch, the driver treats zero returned records without an error as invalid progress.

Linux and Android build the reviewed raw `recvmmsg`/`sendmmsg` backend. The structs use x/sys/unix ABI types and fixed storage, the Go RawConn keeps descriptor lifetime and poller integration, and the nonblocking syscall callbacks preserve runtime liveness. ENOSYS falls back before any record has committed. Darwin uses repeated nonblocking recvmsg/sendmsg calls, draining immediately ready records without waiting to fill. **Darwin still pays one syscall per datagram plus a possible final EAGAIN probe.** The fallback makes batches available to crypto and native bridges; it does not claim a Darwin mmsg syscall reduction. Other platforms retain scalar Conn behavior. Sources: [winn_protocol_experimental/winn3/carrier/batch_linux.go:14](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_linux.go:14), [winn_protocol_experimental/winn3/carrier/batch_darwin.go:13](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_darwin.go:13), [winn_protocol_experimental/winn3/carrier/batch_other.go:3](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_other.go:3).

x/net's batch wrappers were reviewed rather than assumed allocation-free. Its Linux receive path converts socket addresses to net.Addr objects; the reviewed Darwin wrapper also allocates iovec state. An independent Darwin wrapper probe measured 224 B/op and eight allocations versus zero for the plain netip-based receive boundary. The candidate uses fixed raw descriptors to meet the warmed allocation contract. Official API/source references are listed below and the pinned module cache was inspected.

### Lifetime and cancellation

The loop binds one exact generation context before exposing the carrier to read/write. Owned sockets register one context.AfterFunc for that generation, not for each packet. Borrowed sockets do not set shared deadlines or close the lender's descriptor: nonblocking attempts wait on a reusable 1 ms timer, local close signal and context. That preserves other socket users but has an idle polling cost. Binding while IO is active, rebinding an instance, or passing another context after binding is refused. Migration creates a new carrier instance. A binding refusal now occurs before changing the session message size. Run initialization and migration are serialized. Sources: [winn_protocol_experimental/winn3/carrier/batch_unix.go:126](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_unix.go:126), [winn_protocol_experimental/winn3/carrier/batch_unix.go:205](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_unix.go:205), [winn_protocol_experimental/winn3/driver/loop.go:956](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/loop.go:956).

Legacy unbound operations keep per-operation context handling. The zero-allocation assertion applies to initialized, bound successful operations with reusable buffers, not setup, errors, named-zone resolution after a peer change, or the allocating Recv API. The transmit sockaddr cache avoids repeated named IPv6 interface lookup. The code normalizes IPv4-mapped net.IP addresses before choosing the sockaddr matching the actual socket family. Independent review and the full reconnect tests caught both dual-stack and mapped-address mistakes during development; the final regressions pass.

### Partial IO, filtering and offload

SendBatch returns the exact committed input prefix. The loop retries a short successful suffix using the same ciphertext storage; it does not reseal. A send error keeps the existing lossy UDP policy: count the unsent suffix and drop it, never retransmit a committed prefix. A batch count outside bounds or zero progress without error is a configuration failure. Receive processes a valid prefix before an accompanying error and rejects a retired generation. The 65-packet integration test forces short send prefixes and verifies exact order, contents and no duplicates. Sources: [winn_protocol_experimental/winn3/driver/batch_loop.go:14](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/batch_loop.go:14), [winn_protocol_experimental/winn3/driver/batch_loop_test.go:108](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/batch_loop_test.go:108).

Linux offload is explicitly opt-in through UDPConfig.EnableUDPOffload and only for owned sockets. GSO joins already authenticated complete datagrams of equal size, allowing one shorter final record. A different size starts another group. The aggregate is limited to 65,507 bytes and 32 records even where a kernel permits more. No padding is added after encryption and no AEAD spans segments. The path's individual datagram ceiling still applies. A 65,507-byte aggregate ceiling is conservative for IPv6 too; it is not an inner MTU or permission to fragment.

GRO uses a single 65,535-byte staging buffer, validates the native-endian ancillary segment size, and splits into complete descriptors before token lookup or AEAD. It rejects MSG_TRUNC, MSG_CTRUNC, duplicate/malformed control, impossible sizes and counts, empty input, and overlarge aggregates. Up to 128 segments can be retained across caller batches, while sends stay at 32. Current upstream Linux's segment constant and the man page differ; accepting a bounded receive suffix avoids assuming every sender uses this candidate's transmit cap. Every segment remains independently authenticated. Mixed/short-tail and corrupt-record tests execute on the local Linux kernel. Sources: [winn_protocol_experimental/winn3/carrier/batch_linux.go:77](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_linux.go:77), [winn_protocol_experimental/winn3/carrier/batch_unix.go:353](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_unix.go:353), [winn_protocol_experimental/winn3/carrier/batch_unix.go:563](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_unix.go:563).

Capability fallback happens only with a zero committed prefix. Injected unsupported-offload and partial-send tests are fault-injection evidence, not claims that those errors arose naturally on the test NIC. Foreign packets and invalid input cannot advance LastDelivered. Pending GRO segments are re-filtered after peer changes and are not counted twice when drained. Ordinary receive staging uses the path ceiling plus one byte, permitting detection of oversize records without 32 full 64 KiB buffers per session. Receive copies into caller-owned slots; zero allocation is not zero copy.

### Gateway closure work

The production gateway's `server.readLoop` calls ReadFromUDPAddrPort, queues through Pipe.Deliver, and sends through a WriteToUDPAddrPort callback. Its optional cover splitter has another scalar read/copy/queue. These paths do not become mmsg/GSO/GRO paths because the client UDP class changed. Sources: [winn_protocol_experimental/cmd/winn3-gateway/main.go:1683](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cmd/winn3-gateway/main.go:1683), [winn_protocol_experimental/cmd/winn3-gateway/main.go:1906](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cmd/winn3-gateway/main.go:1906), [winn_protocol_experimental/cmd/winn3-gateway/cover_demux.go:107](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cmd/winn3-gateway/cover_demux.go:107).

An explicit NewBatchPipe wrapper is supplied for queue batching. Scalar Pipe remains scalar, because adding methods to it would promote SendBatch through wrappers that override Send and bypass their behavior. The existing gateway does not select the wrapper. Completing gateway activation requires one shared socket receiver, bounded per-session dispatch batches, and one shared egress owner that groups by authenticated destination and preserves each session's prefix. The cover classifier must split before protocol dispatch while carrying the same ownership metadata. No per-session wrapper may independently consume the shared socket. This study does not present that unsupplied gateway integration as implemented.

## Stage 4: native host boundaries

### Apple C and Swift arrays

The actual old production exports were WinnTunnelWriteInbound and WinnTunnelReadOutbound; the singular WinsWinn3EnqueuePacket named in the request was not the baseline symbol. The new additive plural pair is WinsWinn3EnqueuePackets/WinsWinn3DequeuePackets. The original scalar ABI remains compatible. Sources: [winn_protocol_experimental/cdatapath/winn_datapath_batch.go:113](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_datapath_batch.go:113), [winn_protocol_experimental/cdatapath/winn_datapath_batch.go:149](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_datapath_batch.go:149), [apple/WinsTunnelCore/WinsWinn3Datapath.swift:384](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/apple/WinsTunnelCore/WinsWinn3Datapath.swift:384).

The 64-bit descriptor has a pointer at offset 0, uint32 length at 8, capacity at 12, family at 16, reserved at 20, and stride 24. Count is 0 to 32; stride, alignment, overflow, capacity, reserved fields, family/version and descriptor-buffer overlap are checked. Dequeue destination buffers cannot overlap. All descriptors are validated before queue/counter/output effects. An accessible allocation and exclusive caller access remain C ABI preconditions; a raw pointer cannot prove memory accessibility. The generated header and both curated declarations compile against one another.

Enqueue copies into Go-owned queue storage while holding the queue lock. It preserves the existing 256-packet drop-oldest policy and eviction counters. Dequeue waits only for the first record, then returns the available prefix. A short output leaves the head queued, with TOO_LARGE if nothing was copied or the positive completed prefix otherwise. Close is serialized with queue operations and wakes waiters; registry handle ownership prevents stale handles from naming new sessions. No Go slice or unpinned Go pointer escapes to Swift.

Swift validates the whole readPackets callback's packet/protocol metadata, chunks at 32, and nests Data.withUnsafeBytes closures so every source remains valid for the single foreign call. A 70-packet callback produces exactly 32,32,6, verified in the harness. Inbound dequeue uses reusable native storage, converts returned slices to Data arrays, and makes one writePackets call per positive batch. The result of writePackets controls acceptance counters. Both plural symbols and the layout must be available; absent or partial exports choose scalar compatibility in both directions. Sources: [apple/WinsTunnelCore/WinsWinn3Datapath.swift:422](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/apple/WinsTunnelCore/WinsWinn3Datapath.swift:422), [apple/WinsTunnelCore/WinsWinn3Datapath.swift:544](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/apple/WinsTunnelCore/WinsWinn3Datapath.swift:544), [winn_protocol_experimental/cdatapath/winn_packet_batch.h:11](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_packet_batch.h:11).

The candidate adds both exports to the Apple archive symbol list and all six iOS/macOS force-retention link configurations. A local dead-strip executable resolves both through dlsym. This proves local symbol retention, not a signed app's activation. No provider source change was needed because the providers already use the shared Swift pump. Copies and some Swift/C ABI allocations remain; the improvement is foreign-call and packetFlow amortization.

### Android pooled packets and unchanged wire protocol

The chosen branch uses bounded reusable storage and batched framed stream IO, not direct JNI TUN-FD ownership. The actual WNN3 protocol has a 16-byte header and a four-byte little-endian length at offset 8. Concatenating complete existing frames preserves compatibility. A bare four-byte framing replacement would break the channel. Sources: [android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt:10](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt:10), [android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:74](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:74), [android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt:40](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt:40).

The per-packet ArrayBlockingQueue/ByteArray allocation becomes a bounded slab/ring with reusable slots and generation tagging. Each device retains its reader to preserve the existing Android interface-promotion behavior. Rebind invalidates queued, drained and late-returning old-generation packets; the final batch send checks generation while serialized with rebind. Read/write errors wake the bridge, oversize or short buffers are refused rather than truncated, and close releases waits. An old kernel read can remain parked until Android returns; the existing one-promotion lifecycle bounds that retained thread, not arbitrary unlimited rebinds.

WinnV3FramedStreamTransport accumulates frames into reusable buffers, returns already buffered complete records without waiting for batch fill, and serializes batch/control/descriptor writes with one lock. The descriptor handoff byte stays attached to the existing ancillary FD transfer. Partial headers/payloads are retained correctly; truncated EOF and partial write failures latch the transport unusable so later frames cannot be misparsed. The real LocalSocketWinnTransport now uses this adapter. The shared v2 bridge tests were rerun because that adapter serves existing code too. Source: [android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt:523](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt:523).

The JVM fixtures prove 32 frames become one write plus flush, 40 buffered frames need one source read, and 64 queued bridge packets use two batch writes. These are Java API call counts. Physical TUN reads and writes remain one packet per operation, and stream writes may require more than one kernel operation. Actual SCM_RIGHTS, Android shutdown, handover, power and packet throughput were not exercised.

The connected Motorola phone was discovered, but no candidate APK was available. The required formal release producer stopped at `ReleaseInputIndex is required for every Android release build`. The direct macOS helper also correctly refused invocation without the formal producer. No phone uninstall, install or launch was performed. The required phone smoke test is **BLOCKED**, not passed. Evidence: [android_release_blocker.txt](stages345_astra/android_release_blocker.txt). Once a valid candidate release input index and APK exist, follow AGENTS.md's uninstall-first rule, install the exact latest release APK, launch, inspect logcat, and then measure physical VPN behavior. An older APK cannot validate these changes.

### Windows direct Wintun runtime

`main_windows.go` now dispatches `--in-process-candidate` before binding the old inner UDP relay. In that mode one process owns Wintun, the real Winn session, the outer carrier and the TUN validator. There is no inner UDP socket, no packet channel, and no child datapath process. Native receive copies into caller storage then releases the ring lease exactly once. Native send writes to the ring directly. Ring-full returns an error and a drop count, never RxPackets credit or promotion. Sources: [windows/winn3_engine/main_windows.go:3](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/main_windows.go:3), [windows/winn3_engine/direct_device.go:40](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_device.go:40), [windows/winn3_engine/direct_windows.go:22](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_windows.go:22).

A close excludes new operations, wakes native receive, waits for active ring users, and only then ends the session and closes the adapter. The process supplies a two-second cancellation bound for a stuck native call or stdout pipe, leaving reclamation to OS process teardown instead of freeing a ring under active access. LocalSystem, the original stop-event singleton, strict PQ and both gateway attestation keys remain required.

The candidate reads one protected profile path from private stdin, emits a ready line and normal status JSON, and treats EOF or a second line as shutdown. The profile must select `{"kind":"wintun-direct","name":"winsvpn3"}` with no host port. Protected-file checks, bounded input, duplicate/case-variant keys, endpoint/assignment validation, strict-mode and dual-auth checks run before device creation. Sources: [winn_protocol_experimental/winn3/hostqueue/runtime.go:73](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/runtime.go:73), [winn_protocol_experimental/winn3/hostqueue/profile.go:4](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/profile.go:4), [windows/winn3_engine/direct_control.go:11](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_control.go:11).

**The default supervisor still launches the original two-process relay.** It does not select this flag or emit the direct profile/control pipe. Served-descriptor authentication, selected-node binding, installed outer exclusion, address/route/MTU/DNS posture, echo proof and promotion orchestration must surround this candidate. A profile string is not proof of an installed route. Source compilation and the authenticated synthetic native-device test do not prove Windows device operation.

The legacy command's promotion predicate was restored byte-for-byte after conformance tests objected to moving it. The direct candidate has the same tested predicate, gate carrying plus validated RxPackets. Key decoding/custody helpers are shared; remaining duplicated setup/status code needs consolidation before default supervisor adoption. No shipping source was silently switched to the experimental Windows mode.

## Stage 5: ordered multicore crypto

The core supplies CryptoPool, SealSlot and opaque OpenSlot tickets; the frame driver supplies PollBatchInto and ReceiveSlot/DeliverBatch. One lazy pool per Driver has at most min(GOMAXPROCS,32) workers and 32 job slots. A later GOMAXPROCS change resizes between batches. Worker jobs execute raw ChaCha20-Poly1305 over disjoint storage with immutable epoch AEAD references and private nonce arrays. They do not call mutex-serialized Session.Seal/Open. Source: [winn_protocol_experimental/winn3/core/batch.go:23](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/batch.go:23).

Transmit preparation runs on the session owner under the driver mutex. It projects counter/message/byte limits before accepting additional data jobs. Core sendMu reserves counters and bytes sequentially, then spans the bounded worker join. Short output validation occurs before queue or nonce mutation. A canceled/failed send cannot rewind a reservation; the wire counter may have gaps, never reuse. Data frames leave the queue only after successful sealing. Completed slots are emitted in reservation order regardless of worker completion order. Sources: [winn_protocol_experimental/winn3/core/batch.go:127](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/batch.go:127), [winn_protocol_experimental/winn3/session/batch.go:78](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch.go:78).

Receive lookup is sequential but consumes nothing. Parallel AEAD creates speculative tickets. Preview identifies an authenticated frame/control boundary; commit then rechecks the current session/epoch/token window and accepts each token once. Corrupt duplicate and malformed authenticated length do not consume the genuine token. A missing token that becomes visible after window refill, or an epoch change, triggers current-key lookup/decryption. Duplicate in-flight tickets cannot both commit. Preview plaintext is never delivered before commit. Sources: [winn_protocol_experimental/winn3/core/batch.go:201](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/batch.go:201), [winn_protocol_experimental/winn3/core/batch.go:312](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/batch.go:312), [winn_protocol_experimental/winn3/session/batch.go:217](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch.go:217).

Every epoch-changing control path stays on the shared scalar assembly/handler path. All earlier workers have joined before an ACK/PQ after-hook runs. The old-epoch ACK exists before the new keys are installed. New output follows old output in the returned sequence; callers must send that prefix before polling again. No worker retains an old AEAD reference after completion. The core direction locks exclude rekey and wipe until work joins. This is an in-memory epoch barrier; UDP still permits loss/reordering, so the existing ACK-loss timeout and confirmation rules remain necessary.

The driver mutex deliberately spans bounded batches. AEAD calls run in parallel within a batch; send and receive batches still serialize against each other at that driver mutex. The pool is bounded per session, not globally across a gateway. Idle/first-use/control/error/resizing paths can allocate. The underlying AEAD's internal key copies remain subject to Go GC, as in the existing wipe contract.

Receive scratch and packet descriptor capacity are supplied by the caller. Parser frame storage now grows to the actual message need rather than reserving 699,040 bytes per driver. The loop wipes borrowed packet storage after synchronous host delivery. StopCryptoWorkers joins and retires the pool after Run's reader/writer shutdown without changing session key/state lifecycle; a later explicit batch API can create a new pool with monotonic counters. Terminate closes workers and wipes owned storage. Sources: [winn_protocol_experimental/winn3/session/batch.go:47](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch.go:47), [winn_protocol_experimental/winn3/driver/batch_loop.go:62](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/batch_loop.go:62), [winn_protocol_experimental/winn3/session/batch_lifecycle_test.go:10](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch_lifecycle_test.go:10).

The first implementation intentionally returns control/noise prefixes and respeculates a suffix on the next call. An adverse sequence of controls can therefore repeat speculative AEAD work, bounded by the 32-slot batch. A persistent ticket iterator with epoch-aware invalidation is a later optimization, not a claim made for these bytes. The retained scalar PollInto baseline also has a reproduced short-buffer queue-consumption defect; the new batch preflight avoids it, but this study does not claim the old scalar API was repaired.

## Performance evidence and limits

All byte rates below are decimal payload MB/s for the named synthetic boundary. Core batch values are per batch; divide ns/batch by packet count before comparing packet cost. These are short local samples with other verification activity, not controlled physical acceptance.

| GOMAXPROCS | Scalar 1200-byte core pair MB/s | 32-packet core pair MB/s | 1-packet worker batch MB/s |
| --- | ---: | ---: | ---: |
| 1 | 520.36 | 460.88 | 412.04 |
| 2 | 520.50 | 556.11 | 285.41 |
| 4 | 517.16 | 597.10 | 316.36 |
| 8 | 519.61 | 715.23 | 314.58 |

All reported samples above show 0 B/op and 0 allocs/op at the warmed core boundary. At eight CPUs, the 32-record batch improves this local core pair by about 38 percent over scalar, while a one-record worker batch is slower. At one CPU the 32-record batch is slower too. This supports testing a batch/worker threshold; it does not support a universal multicore speedup or a production default of one worker per available CPU. Evidence: [final_crypto_benchmarks.txt](stages345_astra/final_crypto_benchmarks.txt).

Local Linux arm64 GSO/GRO and ordinary mmsg benchmarks also show zero warmed Go heap allocations. They include a local socket round trip without Winn session/host traffic. The full final Linux log records those values and which offload tests actually ran: [final_linux_carrier.txt](stages345_astra/final_linux_carrier.txt). No syscall trace or NIC hardware-offload proof was captured. A software-offloaded loopback success is not hardware or WAN evidence.

A complete physical benchmark must freeze both endpoint artifacts and record inner payload size, outer ceiling, padding, MTU, batch size, actual worker count, CPU quota, kernel, selected native bridge, socket grants and enabled offload. Measure useful bytes at the far end, packet counts/drops, allocations, CPU, syscalls per delivered packet, p50/p99 latency, memory and phone power. Compare scalar/candidate with 64/512/1200/MTU payloads, mixed sizes, IPv4/IPv6, one and many sessions, duplex traffic, idle bursts, loss/reorder and rekeys. Match these parameters for AWG parity comparisons. Run 1/8/16/32 packet batches and CPU 1/2/4/8 with warmup and repeated samples; report regressions as well as wins. No quantitative Amdahl speedup is asserted without measured serial fractions.

## Verification ledger

| Check | Result | Evidence |
| --- | --- | --- |
| Final `GOFLAGS=-buildvcs=false go test -race ./winn3/...` | PASS, all tested packages including redteam/conform/driver | [final_winn3_race.txt](stages345_astra/final_winn3_race.txt) |
| `go vet ./winn3/... ./cdatapath ./cmd/winn-datapath` | PASS, no diagnostics | [final_vet.txt](stages345_astra/final_vet.txt) |
| Core/session adverse batch tests | PASS through full race suite | New batch_test.go files in exact patch |
| Strict `GOEXPERIMENT=cgocheck2`, race, `winn3_batch_test` C ABI tests | PASS | [final_cgo_race.txt](stages345_astra/final_cgo_race.txt) |
| Swift batch/scalar/partial-symbol harness | PASS in all three modes | [final_swift_batch.txt](stages345_astra/final_swift_batch.txt) |
| Apple original host-contract harness against new archive | PASS, 338/338 | [final_apple_host_contract.txt](stages345_astra/final_apple_host_contract.txt) |
| Dead-strip link resolves both plural exports | PASS, local macOS executable | [final_apple_dead_strip.txt](stages345_astra/final_apple_dead_strip.txt) |
| Kotlin production compile and JVM tests | PASS, 136 tests | [final_kotlin.txt](stages345_astra/final_kotlin.txt) |
| Windows portable direct-device race suite | PASS | [final_windows_portable_race.txt](stages345_astra/final_windows_portable_race.txt) |
| Direct runtime and desktop-command race tests | PASS | [final_direct_runtime_race.txt](stages345_astra/final_direct_runtime_race.txt), [final_conform_runtime.txt](stages345_astra/final_conform_runtime.txt) |
| Windows amd64/arm64 executable builds | PASS, execution on Windows unverified | [final_windows_crossbuild.txt](stages345_astra/final_windows_crossbuild.txt) |
| Linux arm64 real-kernel carrier suite | PASS, 174 top-level tests, zero skips | [final_linux_carrier.txt](stages345_astra/final_linux_carrier.txt) |
| Linux amd64/arm64, Android arm64, Darwin amd64, Windows amd64/arm64 package crosscompile | PASS, compile only; explicit no-op foreign test runner | [final_crosscompile.json](stages345_astra/final_crosscompile.json) |
| Existing ruled invariants | Static clauses report 59+6 PASS; Git-backed clauses UNVERIFIED because metadata is incomplete | [final_rulings.txt](stages345_astra/final_rulings.txt), [final_rulings_stderr.txt](stages345_astra/final_rulings_stderr.txt) |
| Patch application and all final changed-file hashes | PASS | [patch_apply_verification.txt](stages345_astra/patch_apply_verification.txt) |
| Physical phone smoke, signed Apple install, Windows Wintun run, WAN speed, cloud proof | BLOCKED or UNVERIFIED as detailed above | No acceptance claimed |

Linux execution used local Colima, Ubuntu 24.04 image digest `sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517`, Linux 6.8.0-138-generic aarch64, and `--network none` with loopback only. The first main-lane invocation failed because Colima did not mount host /tmp; the next lacked the source files required by source-inspection tests. The corrected final invocation mounted the exact carrier source and conformance fixtures and passed. Neither failed setup was counted as test acceptance.

The implementation suites test invalid tails before mutation, zero/oversize batches, partial IO prefixes, scatter boundaries, forged/genuine duplicates, replay-window refill, far epochs, old-key ACKs, counter exhaustion, out-of-order worker completion, simultaneous close/rekey/wipe, resource retirement, stale TUN generations, stream truncation, FD-writer serialization, C ownership, short native outputs and ring-full accounting. Tests requiring the C tag were run with it; a no-tests invocation is not evidence.

Reproduce the portable checks from this workspace with:

```sh
python3 docs/evidence/stages345_astra/verify_candidate.py --java '/Applications/Unity/Hub/Editor/6000.3.23f1/PlaybackEngines/AndroidPlayer/OpenJDK/bin/java' --android-jar '/Applications/Unity/Hub/Editor/6000.3.23f1/PlaybackEngines/AndroidPlayer/SDK/platforms/android-37.0/android.jar'
```

The script verifies the source hashes, regenerates the existing redteam fixture, and executes the named portable checks. It is a Darwin-host suite and does not manufacture device or Linux-runtime acceptance. Detailed lane commands and observations remain available in [carrier.md](stages345_astra/carrier.md), [apple.md](stages345_astra/apple.md), [android.md](stages345_astra/android.md), [windows.md](stages345_astra/windows.md), [crypto.md](stages345_astra/crypto.md) and [review.md](stages345_astra/review.md). Those reports describe earlier lane snapshots. This final report supersedes their stale notes about unresolved reconnects, scalar loop wiring, parser preallocation and the moved promotion predicate.

## Integration sequence and remaining engineering

1. Review and apply the exact snapshot patch to a verified source-of-record checkout. Verify the original hashes for every modified file before applying. Do not transplant it onto a presumed SHA. Run the full local suites and the real ruling checks in that complete repository.
2. Validate batching with offload disabled first. Add explicit runtime observability for actual batch sizes and worker selection. Enable GSO/GRO only in a controlled candidate with recorded capability grants. Finish the shared gateway socket/cover-demux batching before interpreting whole-tunnel speed results.
3. Produce Apple slices with the new exports, verify final app symbol retention and that the array path is selected, then test installed iOS/macOS tunnels. Create the Android candidate release input index through the existing authorized workflow and run the required clean-install phone smoke on the exact APK.
4. Integrate the Windows supervisor with the direct profile/control/status protocol, protected descriptors, route-exclusion and promotion lifecycle. Remove its obsolete inner loopback setup only as part of that complete transaction. Recheck Wintun lease/teardown on both Windows architectures.
5. Benchmark the worker threshold and cap under actual phones, desktop CPUs and gateway session counts. Keep sequential reservation, prefix emission and epoch barriers invariant while tuning dispatch. A global gateway admission budget is still needed beyond a per-session bound.
6. After independent defensive review and target acceptance, use the project's normal fresh-proof deployment process if separately authorized. This study performs no such deployment.

No blanket GO for shipping or wire-speed parity is supported. The implementation-study deliverable is complete and reproducible; the product rollout is incomplete in the explicitly named scopes.

## Official references checked live

Retrieved 2026-09-14. Exact pinned package sources were also inspected locally. Tagged web fetch failures were recorded in lane reports rather than replaced with invented contents.

- [Go ipv4 PacketConn API](https://pkg.go.dev/golang.org/x/net/ipv4) and [upstream batch dispatch](https://raw.githubusercontent.com/golang/net/master/ipv4/batch.go): platform semantics and batch prefix behavior.
- [Linux UDP manual](https://man7.org/linux/man-pages/man7/udp.7.html), [recvmmsg](https://man7.org/linux/man-pages/man2/recvmmsg.2.html), [sendmmsg](https://man7.org/linux/man-pages/man2/sendmmsg.2.html): truncation, offload ancillary data and syscall results.
- [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html) and [current UDP header](https://raw.githubusercontent.com/torvalds/linux/master/include/linux/udp.h): software/hardware distinction and current bounded segment count.
- [Linux TUN/TAP](https://docs.kernel.org/networking/tuntap.html): packet device and explicit multiqueue boundary. UDP mmsg is not a TUN read primitive.
- [Apple readPackets](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets%28completionhandler%3A%29), [writePackets](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets%28_%3Awithprotocols%3A%29), [withUnsafeBytes](https://developer.apple.com/documentation/foundation/contiguousbytes/withunsafebytes%28_%3A%29): packet/protocol arrays and closure-scoped storage.
- [Android VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder), [LocalSocket](https://developer.android.com/reference/android/net/LocalSocket), [InputStream](https://developer.android.com/reference/java/io/InputStream): TUN ownership, ancillary FD handoff and partial stream reads.
- [Pinned Wintun Go session binding](https://git.zx2c4.com/wintun-go/tree/session.go?id=0fa3db229ce2) and [Wintun session source](https://git.zx2c4.com/wintun/tree/api/session.c): receive lease, send ring and end-session lifetime.
- [Go cgo](https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers), [Go memory model](https://go.dev/ref/mem), [cipher.AEAD](https://pkg.go.dev/crypto/cipher#AEAD), [pinned ChaCha20-Poly1305 implementation](https://raw.githubusercontent.com/golang/crypto/v0.54.0/chacha20poly1305/chacha20poly1305.go): pointer lifetime, synchronization, nonce and implementation-specific parallel safety. Arbitrary AEAD implementations are not presumed concurrently safe.

## Complete exact code diffs and source index

The companion unified patch is [candidate.patch](stages345_astra/candidate.patch), SHA-256 `82734deb53303127b74a3afe2d72529c15567b0b35e93681beece3288623fd83`. All 56 changed/new files are included below with complete hunks and exact paths. The patch applied successfully to the original snapshot and reproduced every final changed-file hash. No diff is a placeholder or an omitted implementation.

Some removed or context lines in the original repository contain long-dash typography. To preserve those exact bytes while keeping this Markdown free of those characters, those individual diff parts are represented as a JSON array of complete patch lines. Decode by joining the strings. Other parts are ordinary diff fences. This is a reversible representation, not a source edit or abbreviated diff.

Recover the identical patch directly from this report:

```sh
python3 docs/evidence/stages345_astra/extract_study_patch.py docs/evidence/winn3_stages345_astra_study.md /tmp/winn3-stages345-from-study.patch
```

The extractor prints the patch hash above. Apply only in a source-matched checkout after checking its original-file hashes. The candidate manifest gives each before/after SHA-256. New-file diffs start at /dev/null. Patch context preserves existing code and comments, including legacy terminology.

| Exact candidate file | Final lines | Final SHA-256 |
| --- | ---: | --- |
| [android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt:1) | 565 | `e7666c531974261cd33093ad54423b4d60912f442830037479db48b7d29733b6` |
| [android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:1) | 378 | `a70a1bb41f9225e5269d07fa73e80755852af8ad640436d7f7529783f0b51ceb` |
| [android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt:1) | 526 | `f1ca9b4c5dd10e13cac1cad8cef9c6f3e12844fc6a7c99a3262a5adf1656df79` |
| [android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt:1) | 228 | `ed3afc49fba4522915dd4892be1cd092e9d9be2adeb349a335066facd2c678d5` |
| [android/app/src/test/kotlin/org/winsvpn/app/WinnV3AndroidTunBatchTest.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/test/kotlin/org/winsvpn/app/WinnV3AndroidTunBatchTest.kt:1) | 268 | `0bbd3dd8e704351f9791834e50df26b12c35aaaa5b85d2a8d46fb7e4f437664b` |
| [android/app/src/test/kotlin/org/winsvpn/app/WinnV3BridgeBatchTest.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/test/kotlin/org/winsvpn/app/WinnV3BridgeBatchTest.kt:1) | 152 | `1712cbfb56826b2d3486fbe1890ad1695f2d685eca543f6c9310d70d2226d7b7` |
| [android/app/src/test/kotlin/org/winsvpn/app/WinnV3PacketBatchTest.kt:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/test/kotlin/org/winsvpn/app/WinnV3PacketBatchTest.kt:1) | 275 | `96c4eeab6e9578720351a3d756d6573a2155005aaacfcf831296d97fe314e9cc` |
| [android/app/src/test/run_winn3_batch_tests.py:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/android/app/src/test/run_winn3_batch_tests.py:1) | 110 | `b3f5f84d784d8f1ab7f60d65c04d265007a06619fcf59b6debc5d3034af10375` |
| [apple/EngineWrappers/WinnTunnel.h:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/apple/EngineWrappers/WinnTunnel.h:1) | 399 | `1d447889e5bfce8c5343b580577c0ec61333e96e8daeb1358a7e0b8f4589dfab` |
| [apple/EngineWrappers/WinnTunnelTestDouble.c:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/apple/EngineWrappers/WinnTunnelTestDouble.c:1) | 468 | `cb8d98dc672f4845b03e4fff49ef036b52547e08a4770ad4f5d058eecb1adaf5` |
| [apple/WinsTunnelCore/WinsWinn3Datapath.swift:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/apple/WinsTunnelCore/WinsWinn3Datapath.swift:1) | 694 | `645ada0a0f64e8ccb0025630178b3ab00b255113d759a35c5ac342620bb41c80` |
| [ios/Runner.xcodeproj/project.pbxproj:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/ios/Runner.xcodeproj/project.pbxproj:1) | 1728 | `51f781987a0c23244ae02830fb124209288c8c3d676f9f16b3b5e2a8eeeb8b9c` |
| [macos/Runner.xcodeproj/project.pbxproj:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/macos/Runner.xcodeproj/project.pbxproj:1) | 1283 | `6985ba1520227579a550eca9dee75253f3d5ad47cc15d79f1f4dc4c062bdc18a` |
| [tools/build_winn_protocol_engine.sh:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/tools/build_winn_protocol_engine.sh:1) | 2470 | `3cc2e11ae80106b3519b176a0e41db88789f38318f3784c1d2d0a2fdb359e386` |
| [windows/winn3_engine/direct_control.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_control.go:1) | 48 | `375a5ab2f017a8b1883f8e18a01410bac92ecb9961b61a4936cc6cec24e8fbce` |
| [windows/winn3_engine/direct_device.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_device.go:1) | 113 | `6c9a851bbcd30f6909fbf4229def678c2229985c8cea37c61df256c2e3dd9f83` |
| [windows/winn3_engine/direct_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_test.go:1) | 186 | `8032125df10399242caaca2a3c9286181691ecc5bf34b12f5f4c56e8896d936b` |
| [windows/winn3_engine/direct_windows.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/direct_windows.go:1) | 108 | `d21093214c256b755eddbc145776b619ddf1e4a27406d61e410fd0caa37d79af` |
| [windows/winn3_engine/go.mod:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/go.mod:1) | 47 | `e126549eebc2a5aa7990c0b64db2df9f92fe9aa266c98c3ac90237f459adf962` |
| [windows/winn3_engine/go.sum:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/go.sum:1) | 8 | `13b99057cb9a43f017be4bdb9b03bafb43bf252322849db90d8f1913af337e91` |
| [windows/winn3_engine/main_windows.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/windows/winn3_engine/main_windows.go:1) | 553 | `28867bb72739fdd890fb950e28f4d14fd90563aace02a1eac26ae640171132da` |
| [winn_protocol_experimental/cdatapath/batch_test_support.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/batch_test_support.go:1) | 61 | `ac413083766fa1ee5232070537859efc77567881bae8b103ba1876fff57b4b7f` |
| [winn_protocol_experimental/cdatapath/tests/apple_batch_harness.swift:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/tests/apple_batch_harness.swift:1) | 173 | `5ee8c6fdc10dbcf91371b1dea117e7a419c79cdfe389698843bf86e3566b9933` |
| [winn_protocol_experimental/cdatapath/tests/batch_header_contract.c:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/tests/batch_header_contract.c:1) | 17 | `7fafc1cbe0528dd377ad7100ea4dc88448097ced183144df686f9fa6bc16866f` |
| [winn_protocol_experimental/cdatapath/tests/run_apple_batch_harness.sh:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/tests/run_apple_batch_harness.sh:1) | 26 | `4031fdb9222f785e8ff540a9a9db8a1d10fc49bd6042aafb18b0fc63cbecd7b9` |
| [winn_protocol_experimental/cdatapath/winn_datapath.h:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_datapath.h:1) | 436 | `78794d1eb868ab4b9d02df67e76324804b0aabd06f95524931183f1ae352a27f` |
| [winn_protocol_experimental/cdatapath/winn_datapath_batch.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_datapath_batch.go:1) | 220 | `54016e928f43eb8af9befbf43747ca2ddae52358371d71bb140ef20760fa3cc1` |
| [winn_protocol_experimental/cdatapath/winn_datapath_batch_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_datapath_batch_test.go:1) | 307 | `156f9c88c90695112e6f7271d807ed310f8f8c28bf4d9439259d5093c118e44f` |
| [winn_protocol_experimental/cdatapath/winn_packet_batch.h:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cdatapath/winn_packet_batch.h:1) | 26 | `823c4bef1f4bed2c640b520f82aceab7896e92109c5fa54c3864135918a3ab60` |
| [winn_protocol_experimental/cmd/winn-datapath/winn3_keys.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/cmd/winn-datapath/winn3_keys.go:1) | 296 | `151bdb03e2d9acdf6ea22c323429d63e119690ce2998a5203446897992d4381f` |
| [winn_protocol_experimental/winn3/carrier/batch.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch.go:1) | 104 | `dcb78485651481f1e0a5968e433c0d33a63f6380bc07a3c8ff234ffedf81c17d` |
| [winn_protocol_experimental/winn3/carrier/batch_darwin.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_darwin.go:1) | 49 | `ade67b0a92c207f7c0322c7b8e2ffaf4b807d728d0d430e9820d7747a5f29e01` |
| [winn_protocol_experimental/winn3/carrier/batch_linux.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_linux.go:1) | 106 | `67069526fbbb0fb00e167cc63b799016fb66871afa1aba6cca763f07f414f8d3` |
| [winn_protocol_experimental/winn3/carrier/batch_linux_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_linux_test.go:1) | 373 | `6314079494c0ce0a63bc6465085f7496be433585a30e1905bdbad3d62a788afe` |
| [winn_protocol_experimental/winn3/carrier/batch_other.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_other.go:1) | 21 | `6c1d87c84c942849261639d027a207d509656e14a071803f38f3fb9952818f49` |
| [winn_protocol_experimental/winn3/carrier/batch_pipe.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_pipe.go:1) | 162 | `e1bd5cdc5cde248008d02680d399a7d8568f0e8ebc10de66c766360c588cf4ab` |
| [winn_protocol_experimental/winn3/carrier/batch_pipe_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_pipe_test.go:1) | 118 | `766f8f4e7afa2f0a73c4e4d06e22eddc8a2b921c28e7c8346d4cabacfe8e9b76` |
| [winn_protocol_experimental/winn3/carrier/batch_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_test.go:1) | 564 | `1e44f004ab8fa28cdc631fec508343690c3e4e4c3f33dbb81575e369785d3f21` |
| [winn_protocol_experimental/winn3/carrier/batch_unix.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/batch_unix.go:1) | 711 | `1483f84bb173fb216a52ce7a01cc1c2026f8cf1d0e8336a8aa878479d3fd510e` |
| [winn_protocol_experimental/winn3/carrier/udp.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/carrier/udp.go:1) | 595 | `2d5a24bb1630be59fbb92824b192ddfa9cd29d48967f9aa4d2ef15db1c797ee2` |
| [winn_protocol_experimental/winn3/core/batch.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/batch.go:1) | 324 | `299d993c8888511c30a88fc64832d923fda87dff20d393b48d0855d1483d263b` |
| [winn_protocol_experimental/winn3/core/batch_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/batch_test.go:1) | 467 | `8ad9cf369bec90cd29c818539e93dcf805d8c2b12a45247b5c06d3aa8eb269f2` |
| [winn_protocol_experimental/winn3/core/frame.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/core/frame.go:1) | 141 | `912c67eed54055f414650674cfdbcbc5999671c1acaddd5645ca734ed79a0f05` |
| [winn_protocol_experimental/winn3/driver/batch_loop.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/batch_loop.go:1) | 92 | `678768ff5ac017f25a8d375d0d66ece767914325fc9632a91ba90eeb63d289a1` |
| [winn_protocol_experimental/winn3/driver/batch_loop_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/batch_loop_test.go:1) | 163 | `20e73d604363eec592165270b3a566b25681834ad87e669feb80a338e8d8b9ad` |
| [winn_protocol_experimental/winn3/driver/loop.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/driver/loop.go:1) | 1078 | `98b25f7d4879605c2e86fb57bd8c0ae8e40d1f6e4f056f30167921037a0a7dc0` |
| [winn_protocol_experimental/winn3/hostqueue/carrier.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/carrier.go:1) | 207 | `54eb01778dfc115019d32139fac64d1b10773774e91fd1346e18d0b46811ec2e` |
| [winn_protocol_experimental/winn3/hostqueue/keys.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/keys.go:1) | 97 | `2be835a68d33c469785a43f672bfe08fda70078fb9adf2a68dc68bb1eda79c64` |
| [winn_protocol_experimental/winn3/hostqueue/profile.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/profile.go:1) | 587 | `77ad77a12a28df0ec3fdae206aa6949773f4cbb97567893a6282e64a7193b89b` |
| [winn_protocol_experimental/winn3/hostqueue/runtime.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/runtime.go:1) | 263 | `21ce1feb1d6490d48e19007752b08296888ce5f167ea4b595b975d296d2f5220` |
| [winn_protocol_experimental/winn3/hostqueue/runtime_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/runtime_test.go:1) | 520 | `a93227b088b4878ada6f65a77d3aae0de796d3f2999e95ce9848980fa9fb60ac` |
| [winn_protocol_experimental/winn3/hostqueue/status.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/hostqueue/status.go:1) | 152 | `15304b1efb9db4724e9291373e101542318ba30797ce771e1af1171adf74b935` |
| [winn_protocol_experimental/winn3/session/batch.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch.go:1) | 333 | `db5dfbdee6b710b8304e917c8482ef15a688a522bf03d59c34aa435d1b490806` |
| [winn_protocol_experimental/winn3/session/batch_lifecycle_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch_lifecycle_test.go:1) | 41 | `55b363b92bff567ddf5496014ec65750d024bd2ac94d554586a6a9e14d623a36` |
| [winn_protocol_experimental/winn3/session/batch_test.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/batch_test.go:1) | 336 | `e16ae4655a4912fd9a7aa2e9466ff28d32d20515fca4175dc51da7a3f5c3b438` |
| [winn_protocol_experimental/winn3/session/driver.go:1](/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/astra/winn_protocol_experimental/winn3/session/driver.go:1) | 2516 | `85a49c14c6ed7218345380557f67e0a43c56ed07989e8c66cf33a98c9d4c8efd` |

### android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt

<!-- winn345-patch:diff -->
```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt
@@ -6,7 +6,6 @@
 import android.net.VpnService
 import android.os.Build
 import android.os.ParcelFileDescriptor
-import java.io.BufferedInputStream
 import java.io.File
 import java.io.FileDescriptor
 import java.io.IOException
@@ -521,22 +520,12 @@
         }
     }
 
-    private class LocalSocketWinnTransport(private val socket: LocalSocket) : WinnEngineTransport {
+    private class LocalSocketWinnTransport(private val socket: LocalSocket) : WinnV3BatchTransport {
         private val out: OutputStream = socket.outputStream
-        private val input: InputStream = BufferedInputStream(socket.inputStream, 64 * 1024)
-        private val writeLock = Object()
-
-        // This side is the host, so it accepts engine-to-host opcodes only.
-        private val reader = WinnFrameReader(input, acceptEngineToHost = true)
-
-        override fun writeFrame(opcode: Int, payload: ByteArray) {
-            synchronized(writeLock) {
-                WinnFraming.writeFrame(out, opcode, payload)
-            }
-        }
-
-        override fun sendDescriptor(fd: FileDescriptor) {
-            synchronized(writeLock) {
+        private val stream = WinnV3FramedStreamTransport(
+            input = socket.inputStream,
+            output = out,
+            descriptorSender = { fd ->
                 // Exactly one byte, and nothing else, in this sendmsg: the
                 // engine's -receive-fd path reads it with a one-byte recvmsg
                 // before the frame reader ever runs. Sending more here would
@@ -548,21 +537,29 @@
                 } finally {
                     socket.setFileDescriptorsForSend(null)
                 }
-            }
-        }
-
-        override fun readFrame(): WinnFrame? = reader.read()
-
-        override fun setReadTimeoutMs(timeoutMs: Int) {
-            socket.soTimeout = timeoutMs
-        }
-
-        override fun close() {
-            try {
-                socket.shutdownOutput()
-            } catch (_: Exception) {
-            }
-            socket.close()
-        }
+            },
+            timeoutSetter = { socket.soTimeout = it },
+            socketCloser = {
+                // Shutdown both directions before close to wake blocked I/O.
+                // This callback runs without the stream writer's monitor.
+                try {
+                    socket.shutdownInput()
+                } catch (_: Exception) {
+                }
+                try {
+                    socket.shutdownOutput()
+                } catch (_: Exception) {
+                }
+                socket.close()
+            },
+        )
+
+        override fun writeFrame(opcode: Int, payload: ByteArray) = stream.writeFrame(opcode, payload)
+        override fun writeBatch(batch: WinnV3PacketBatch) = stream.writeBatch(batch)
+        override fun readBatch(batch: WinnV3PacketBatch): Int = stream.readBatch(batch)
+        override fun sendDescriptor(fd: FileDescriptor) = stream.sendDescriptor(fd)
+        override fun readFrame(): WinnFrame? = stream.readFrame()
+        override fun setReadTimeoutMs(timeoutMs: Int) = stream.setReadTimeoutMs(timeoutMs)
+        override fun close() = stream.close()
     }
 }
```

### android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt

<!-- winn345-patch:json -->
```json
[
  "--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt\n",
  "+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt\n",
  "@@ -9,8 +9,6 @@\n",
  " import java.io.FileOutputStream\n",
  " import java.io.IOException\n",
  " import java.net.InetAddress\n",
  "-import java.util.concurrent.ArrayBlockingQueue\n",
  "-import java.util.concurrent.TimeUnit\n",
  " import java.util.concurrent.atomic.AtomicBoolean\n",
  " import java.util.concurrent.atomic.AtomicLong\n",
  " import java.util.concurrent.atomic.AtomicReference\n",
  "@@ -33,7 +31,7 @@\n",
  " internal class WinnV3AndroidTunDevice(\n",
  "     private val pfd: ParcelFileDescriptor,\n",
  "     override val mtu: Int,\n",
  "-) : WinnV3TunDevice {\n",
  "+) : WinnV3SliceTunDevice {\n",
  " \n",
  "     private val input = FileInputStream(pfd.fileDescriptor)\n",
  "     private val output = FileOutputStream(pfd.fileDescriptor)\n",
  "@@ -41,7 +39,11 @@\n",
  "     override fun read(buffer: ByteArray): Int = input.read(buffer)\n",
  " \n",
  "     override fun write(packet: ByteArray, length: Int) {\n",
  "-        output.write(packet, 0, length)\n",
  "+        write(packet, 0, length)\n",
  "+    }\n",
  "+\n",
  "+    override fun write(packet: ByteArray, offset: Int, length: Int) {\n",
  "+        output.write(packet, offset, length)\n",
  "     }\n",
  " \n",
  "     override fun close() {\n",
  "@@ -57,76 +59,44 @@\n",
  " }\n",
  " \n",
  " /**\n",
  "- * [WinnV3IpPacketSeam] over an Android tun interface, built so that a promotion\n",
  "- * can replace the interface **without the engine noticing and without the\n",
  "- * outbound pump ever blocking on the dead one**.\n",
  "+ * Bounded packet slots between the physical tun and the framed stream pump.\n",
  "+ * Each device has its own reader, so a promotion never waits on an old read.\n",
  "+ * One scratch array per reader feeds a fixed MTU-sized slab, with no packet\n",
  "+ * arrays or queue-node allocation. Kernel reads and writes remain per packet.\n",
  "  *\n",
  "- * ## The problem this class exists to solve\n",
  "- *\n",
  "- * Android has no API to change the routes, MTU or resolvers of a live\n",
  "- * `VpnService`; the only mechanism is `Builder.establish()` again, which yields\n",
  "- * a new descriptor and deactivates the old one. So promotion necessarily\n",
  "- * replaces the tun descriptor mid-session \u2014 see [WinnV3Host] \u00a74, which is why\n",
  "- * the host owns the device and the engine's `tun.Device` is this channel-backed\n",
  "- * seam rather than a descriptor.\n",
  "- *\n",
  "- * The naive implementation holds a swappable reference and reads through it.\n",
  "- * That has a defect which only appears on a handset: at the moment of promotion\n",
  "- * the pump is **already blocked inside `read()` on the old descriptor**, so it\n",
  "- * is not looking at the reference at all. Whether that blocked read ever\n",
  "- * returns is Android-runtime behaviour, and if it does not, the pump stays\n",
  "- * parked on a deactivated interface forever. The tunnel would then promote,\n",
  "- * report carrying, and silently send nothing \u2014 the failure mode this whole\n",
  "- * staged design exists to avoid, arriving one layer lower down.\n",
  "- *\n",
  "- * ## The shape that does not depend on that\n",
  "- *\n",
  "- * Each device gets its **own reader thread**, and [readOutgoingPacket] takes\n",
  "- * from a queue instead of from a descriptor. [rebindDevice] starts a reader for\n",
  "- * the new device and abandons the old one. The pump is therefore never blocked\n",
  "- * on the descriptor being replaced, whatever the old read does:\n",
  "- *\n",
  "- *  - if the old read returns or throws, its thread exits and is collected;\n",
  "- *  - if it never returns, one daemon thread stays parked. That is bounded at\n",
  "- *    one per promotion, and there is exactly one promotion per session.\n",
  "- *\n",
  "- * The cost is one array copy per outbound packet. It is paid knowingly: the\n",
  "- * alternative is a correctness property that depends on undocumented behaviour\n",
  "- * of a descriptor that has just been deactivated.\n",
  "- *\n",
  "- * ## Overflow is a drop, not growth\n",
  "- *\n",
  "- * The queue is bounded. A tun reader that outruns the frame channel and grows\n",
  "- * an unbounded queue is a memory bug that presents as an OOM kill in the field;\n",
  "- * dropping is what the link below would do anyway. Drops are counted and\n",
  "- * reported through [onDropped], the same way [WinnAwgLoopbackSeam] reports its\n",
  "- * own \u2014 silence is what let a lossy seam through two \"successful\" proofs.\n",
  "+ * The state monitor covers generation checks, enqueue, drain and invalidation.\n",
  "+ * Independent delivery monitors serialize each direction with rebind without\n",
  "+ * blocking incoming delivery behind an outgoing socket write. A batch drained\n",
  "+ * before a swap must either finish sending before the swap or be discarded.\n",
  "+ * No monitor is held across the physical read or while waiting for queue data.\n",
  "+ * Close invalidates state and wakes consumers before closing the descriptor.\n",
  "  */\n",
  " internal class WinnV3AndroidIpPacketSeam(\n",
  "     initialDevice: WinnV3TunDevice,\n",
  "     private val onDropped: (String) -> Unit = {},\n",
  "     private val onDebug: (String) -> Unit = {},\n",
  "-    queueDepth: Int = DEFAULT_QUEUE_DEPTH,\n",
  "-) : WinnV3IpPacketSeam {\n",
  "-\n",
  "+    private val queueDepth: Int = DEFAULT_QUEUE_DEPTH,\n",
  "+) : WinnV3BatchedIpPacketSeam {\n",
  "     companion object {\n",
  "-        /**\n",
  "-         * Outbound packets held between the tun reader and the frame channel.\n",
  "-         *\n",
  "-         * Chosen to absorb a burst without becoming a buffer that hides a slow\n",
  "-         * channel: at the plan-floor inner MTU this is under 350 kB.\n",
  "-         */\n",
  "         const val DEFAULT_QUEUE_DEPTH = 256\n",
  "-\n",
  "-        /**\n",
  "-         * How long [readOutgoingPacket] waits before looking at the closed flag\n",
  "-         * again. It only bounds shutdown latency; it is not a timeout on\n",
  "-         * anything the peer does.\n",
  "-         */\n",
  "-        const val POLL_MS = 250L\n",
  "-    }\n",
  "-\n",
  "-    private val queue = ArrayBlockingQueue<ByteArray>(queueDepth)\n",
  "+    }\n",
  "+\n",
  "+    private val packetCapacity = WinnV3Bridge.bufferSizeFor(initialDevice.mtu)\n",
  "+    init {\n",
  "+        require(queueDepth in 1..4096)\n",
  "+        require(initialDevice.mtu in 1..WinnFraming.MAX_PAYLOAD_BYTES)\n",
  "+        require(queueDepth.toLong() * packetCapacity <= 16 * 1024 * 1024)\n",
  "+    }\n",
  "+    private val slab = ByteArray(queueDepth * packetCapacity)\n",
  "+    private val lengths = IntArray(queueDepth)\n",
  "+    private var head = 0\n",
  "+    private var count = 0\n",
  "+    private var readerFailure: IOException? = null\n",
  "+    private var readerEnded = false\n",
  "+    private val state = Object()\n",
  "+    private val delivery = Any()\n",
  "+    private val incomingDelivery = Any()\n",
  "+    private val incomingScratch = ByteArray(packetCapacity)\n",
  "     private val device = AtomicReference<WinnV3TunDevice?>(initialDevice)\n",
  "     private val closed = AtomicBoolean(false)\n",
  "     private val dropped = AtomicLong(0L)\n",
  "@@ -136,33 +106,44 @@\n",
  "         startReader(initialDevice, readerGeneration.get())\n",
  "     }\n",
  " \n",
  "-    /** The device the seam is currently reading from. Null once closed. */\n",
  "     fun currentDevice(): WinnV3TunDevice? = device.get()\n",
  "-\n",
  "-    /** Outbound packets dropped because the frame channel was behind. */\n",
  "     fun droppedCount(): Long = dropped.get()\n",
  " \n",
  "     private fun startReader(target: WinnV3TunDevice, generation: Long) {\n",
  "         Thread {\n",
  "-            // Sized from the device's own MTU: the largest packet the kernel\n",
  "-            // can hand up on this interface.\n",
  "-            val buffer = ByteArray(WinnV3Bridge.bufferSizeFor(target.mtu))\n",
  "+            // More than the protocol maximum, so a packet above the configured\n",
  "+            // MTU cannot masquerade as a valid short read into an MTU-sized array.\n",
  "+            val buffer = ByteArray(WinnFraming.MAX_PAYLOAD_BYTES + 1)\n",
  "             try {\n",
  "                 while (!closed.get() && readerGeneration.get() == generation) {\n",
  "                     val n = target.read(buffer)\n",
  "-                    if (n < 0) return@Thread\n",
  "-                    if (n == 0) continue\n",
  "-                    if (!queue.offer(buffer.copyOf(n))) {\n",
  "-                        val total = dropped.incrementAndGet()\n",
  "-                        onDropped(\"outbound queue full at ${queue.size} packets; dropped $total so far\")\n",
  "+                    var overflow = false\n",
  "+                    synchronized(state) {\n",
  "+                        // This must be AFTER read, including a read that returned\n",
  "+                        // after close or rebind deactivated its descriptor.\n",
  "+                        if (closed.get() || readerGeneration.get() != generation) return@Thread\n",
  "+                        if (n < 0) {\n",
  "+                            readerEnded = true\n",
  "+                            state.notifyAll()\n",
  "+                            return@Thread\n",
  "+                        }\n",
  "+                        if (n > target.mtu || n > packetCapacity || n > buffer.size) {\n",
  "+                            throw IOException(\"Winn tun packet exceeds configured MTU\")\n",
  "+                        }\n",
  "+                        if (n > 0) overflow = !enqueue(buffer, n)\n",
  "                     }\n",
  "+                    if (overflow) recordDrop(\"outbound queue full\")\n",
  "                 }\n",
  "             } catch (e: Exception) {\n",
  "-                // A read that fails on a device this seam has already moved off\n",
  "-                // is the expected end of an abandoned reader, not a fault.\n",
  "-                if (!closed.get() && readerGeneration.get() == generation) {\n",
  "-                    onDebug(\"winn3: tun reader ended: ${e.javaClass.simpleName}\")\n",
  "-                }\n",
  "+                val active = synchronized(state) {\n",
  "+                    if (closed.get() || readerGeneration.get() != generation) false\n",
  "+                    else {\n",
  "+                        readerFailure = if (e is IOException) e else IOException(\"Winn tun reader failed\", e)\n",
  "+                        state.notifyAll()\n",
  "+                        true\n",
  "+                    }\n",
  "+                }\n",
  "+                if (active) onDebug(\"winn3: tun reader ended: ${e.javaClass.simpleName}\")\n",
  "             }\n",
  "         }.apply {\n",
  "             name = \"WinsVPN-WinnV3-TunRead-$generation\"\n",
  "@@ -171,92 +152,154 @@\n",
  "         }\n",
  "     }\n",
  " \n",
  "-    override fun readOutgoingPacket(buffer: ByteArray): Int {\n",
  "-        while (!closed.get()) {\n",
  "-            val packet = queue.poll(POLL_MS, TimeUnit.MILLISECONDS) ?: continue\n",
  "-            val n = minOf(packet.size, buffer.size)\n",
  "-            System.arraycopy(packet, 0, buffer, 0, n)\n",
  "-            return n\n",
  "-        }\n",
  "-        return -1\n",
  "-    }\n",
  "-\n",
  "-    /**\n",
  "-     * Injects one packet into the outbound side of the tunnel, exactly where a\n",
  "-     * packet the kernel read off the tun would sit: the bridge's inbound pump\n",
  "-     * takes it next and hands it to the engine as an ordinary `OP_INBOUND`,\n",
  "-     * which validates it by the same inner-IP rules as every other packet.\n",
  "-     *\n",
  "-     * This is the Android shape of the self-starting promotion probe. The host\n",
  "-     * cannot open a raw ICMP socket on Android (no CAP_NET_RAW for apps), so\n",
  "-     * the Windows/Linux \"send an echo through the stack and let the route put\n",
  "-     * it in the tunnel\" has no direct analogue; writing the crafted packet into\n",
  "-     * the seam is the platform's own tunnel-protected path, and it is the\n",
  "-     * STRICTER one: the packet can only leave through the engine toward the\n",
  "-     * configured gateway, never onto the physical default route.\n",
  "-     *\n",
  "-     * Returns false when the seam is closed or the queue is full; both are\n",
  "-     * advisory failures and the caller's bounded retry absorbs them.\n",
  "-     */\n",
  "+    /** Called with state held; admission copies only into preallocated storage. */\n",
  "+    private fun enqueue(packet: ByteArray, length: Int): Boolean {\n",
  "+        if (count == queueDepth) return false\n",
  "+        val slot = (head + count) % queueDepth\n",
  "+        System.arraycopy(packet, 0, slab, slot * packetCapacity, length)\n",
  "+        lengths[slot] = length\n",
  "+        count++\n",
  "+        state.notifyAll()\n",
  "+        return true\n",
  "+    }\n",
  "+\n",
  "+    private fun recordDrop(reason: String) {\n",
  "+        val total = dropped.incrementAndGet()\n",
  "+        onDropped(\"$reason; dropped $total so far\")\n",
  "+    }\n",
  "+\n",
  "+    private fun awaitPacket(): Boolean {\n",
  "+        while (count == 0 && !closed.get()) {\n",
  "+            readerFailure?.let { throw it }\n",
  "+            if (readerEnded) return false\n",
  "+            state.wait()\n",
  "+        }\n",
  "+        if (closed.get()) return false\n",
  "+        readerFailure?.let { throw it }\n",
  "+        return true\n",
  "+    }\n",
  "+\n",
  "+    override fun readOutgoingPacket(buffer: ByteArray): Int = synchronized(state) {\n",
  "+        if (!awaitPacket()) return@synchronized -1\n",
  "+        val n = lengths[head]\n",
  "+        if (n > buffer.size) throw IOException(\"Winn tun destination too small: ${buffer.size} < $n\")\n",
  "+        System.arraycopy(slab, head * packetCapacity, buffer, 0, n)\n",
  "+        head = (head + 1) % queueDepth\n",
  "+        count--\n",
  "+        n\n",
  "+    }\n",
  "+\n",
  "+    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int = synchronized(state) {\n",
  "+        batch.clear()\n",
  "+        if (!awaitPacket()) return@synchronized -1\n",
  "+        batch.generation = readerGeneration.get()\n",
  "+        while (count > 0 && batch.canAppend(lengths[head])) {\n",
  "+            batch.append(WinnFraming.OP_INBOUND, slab, head * packetCapacity, lengths[head])\n",
  "+            head = (head + 1) % queueDepth\n",
  "+            count--\n",
  "+        }\n",
  "+        if (batch.count == 0) throw IOException(\"Winn tun batch destination too small\")\n",
  "+        batch.count\n",
  "+    }\n",
  "+\n",
  "+    override fun writeOutgoingBatchIfCurrent(batch: WinnV3PacketBatch, write: () -> Unit): Boolean =\n",
  "+        synchronized(delivery) {\n",
  "+            if (closed.get() || batch.generation != readerGeneration.get()) return@synchronized false\n",
  "+            write()\n",
  "+            true\n",
  "+        }\n",
  "+\n",
  "     fun injectOutgoingPacket(packet: ByteArray, length: Int): Boolean {\n",
  "-        if (closed.get()) return false\n",
  "-        val copy = packet.copyOf(length)\n",
  "-        if (queue.offer(copy)) return true\n",
  "-        val total = dropped.incrementAndGet()\n",
  "-        onDropped(\"outbound queue full at ${queue.size} packets while injecting; dropped $total so far\")\n",
  "-        return false\n",
  "+        require(length in 1..packet.size && length <= packetCapacity)\n",
  "+        val accepted = synchronized(state) {\n",
  "+            if (closed.get()) return false\n",
  "+            if (length > (device.get()?.mtu ?: 0)) return false\n",
  "+            enqueue(packet, length)\n",
  "+        }\n",
  "+        if (!accepted) recordDrop(\"outbound queue full while injecting\")\n",
  "+        return accepted\n",
  "     }\n",
  " \n",
  "     override fun writeIncomingPacket(packet: ByteArray, length: Int) {\n",
  "-        // Straight to the CURRENT device. An inbound packet that arrives during\n",
  "-        // the promotion window is written to whichever interface is installed\n",
  "-        // at that instant, which is the correct answer either way: before the\n",
  "-        // swap the bootstrap interface is still the host's tun, and after it\n",
  "-        // the promoted one is.\n",
  "-        val target = device.get() ?: return\n",
  "+        require(length in 1..packet.size)\n",
  "+        synchronized(incomingDelivery) {\n",
  "+            val target = device.get() ?: return\n",
  "+            if (closed.get()) return\n",
  "+            if (length > target.mtu) throw IOException(\"Winn inbound packet exceeds configured MTU\")\n",
  "+            target.write(packet, length)\n",
  "+        }\n",
  "+    }\n",
  "+\n",
  "+    override fun writeIncomingBatch(batch: WinnV3PacketBatch, start: Int, end: Int) {\n",
  "+        require(start >= 0 && start <= end && end <= batch.count)\n",
  "+        synchronized(incomingDelivery) {\n",
  "+            val target = device.get() ?: return\n",
  "+            if (closed.get()) return\n",
  "+            // Reject the whole prefix before a device write if any member is invalid.\n",
  "+            for (i in start until end) {\n",
  "+                if (batch.opcode(i) != WinnFraming.OP_OUTBOUND || batch.length(i) > target.mtu) {\n",
  "+                    throw IOException(\"Invalid Winn inbound packet batch\")\n",
  "+                }\n",
  "+            }\n",
  "+            for (i in start until end) {\n",
  "+                if (closed.get()) return\n",
  "+                val n = batch.length(i)\n",
  "+                if (target is WinnV3SliceTunDevice) {\n",
  "+                    target.write(batch.bytes, batch.offset(i), n)\n",
  "+                } else {\n",
  "+                    System.arraycopy(batch.bytes, batch.offset(i), incomingScratch, 0, n)\n",
  "+                    target.write(incomingScratch, n)\n",
  "+                }\n",
  "+            }\n",
  "+        }\n",
  "+    }\n",
  "+\n",
  "+    override fun rebindDevice(newDevice: WinnV3TunDevice) {\n",
  "+        val previous: WinnV3TunDevice?\n",
  "+        synchronized(delivery) {\n",
  "+            synchronized(incomingDelivery) {\n",
  "+                synchronized(state) {\n",
  "+                    if (closed.get()) {\n",
  "+                        newDevice.close()\n",
  "+                        return\n",
  "+                    }\n",
  "+                    // The session's inner MTU is fixed. Enlarging beyond its slab\n",
  "+                    // would truncate packets; fail before replacing the live device.\n",
  "+                    require(newDevice.mtu in 1..packetCapacity)\n",
  "+                    if (device.get() === newDevice) return\n",
  "+                    previous = device.getAndSet(newDevice)\n",
  "+                    val generation = readerGeneration.incrementAndGet()\n",
  "+                    head = 0\n",
  "+                    count = 0\n",
  "+                    readerFailure = null\n",
  "+                    readerEnded = false\n",
  "+                    state.notifyAll()\n",
  "+                    startReader(newDevice, generation)\n",
  "+                }\n",
  "+            }\n",
  "+        }\n",
  "+        // No read on the retired descriptor can enqueue after the state swap.\n",
  "         try {\n",
  "-            target.write(packet, length)\n",
  "-        } catch (e: IOException) {\n",
  "-            if (!closed.get()) onDropped(\"inbound write failed: ${e.javaClass.simpleName}\")\n",
  "-        }\n",
  "-    }\n",
  "-\n",
  "-    /**\n",
  "-     * Replaces the device after a promotion.\n",
  "-     *\n",
  "-     * The engine is not told and must not be: from `winn3/tun`'s side the\n",
  "-     * `Device` is unchanged, which is the property that makes a staged posture\n",
  "-     * possible on this platform at all.\n",
  "-     *\n",
  "-     * The old device is closed AFTER the generation has moved and the new\n",
  "-     * reader is running, so there is no window in which the seam has no reader.\n",
  "-     */\n",
  "-    override fun rebindDevice(newDevice: WinnV3TunDevice) {\n",
  "-        if (closed.get()) {\n",
  "-            newDevice.close()\n",
  "-            return\n",
  "-        }\n",
  "-        val previous = device.getAndSet(newDevice)\n",
  "-        val generation = readerGeneration.incrementAndGet()\n",
  "-        startReader(newDevice, generation)\n",
  "-        onDebug(\"winn3: tun device rebound at generation $generation (mtu=${newDevice.mtu})\")\n",
  "-        if (previous !== newDevice) {\n",
  "-            try {\n",
  "-                previous?.close()\n",
  "-            } catch (e: Exception) {\n",
  "-                onDebug(\"winn3: previous tun device close was incomplete: ${e.javaClass.simpleName}\")\n",
  "-            }\n",
  "+            previous?.close()\n",
  "+        } catch (e: Exception) {\n",
  "+            onDebug(\"winn3: previous tun device close was incomplete: ${e.javaClass.simpleName}\")\n",
  "         }\n",
  "     }\n",
  " \n",
  "     override fun close() {\n",
  "-        if (!closed.compareAndSet(false, true)) return\n",
  "-        val target = device.getAndSet(null)\n",
  "+        val target: WinnV3TunDevice?\n",
  "+        synchronized(state) {\n",
  "+            if (!closed.compareAndSet(false, true)) return\n",
  "+            readerGeneration.incrementAndGet()\n",
  "+            target = device.getAndSet(null)\n",
  "+            head = 0\n",
  "+            count = 0\n",
  "+            state.notifyAll()\n",
  "+        }\n",
  "         try {\n",
  "             target?.close()\n",
  "         } catch (_: Exception) {\n",
  "         }\n",
  "-        queue.clear()\n",
  "     }\n",
  " }\n",
  " \n"
]
```

### android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt

<!-- winn345-patch:diff -->
```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
@@ -186,36 +186,34 @@
         outboundPump = Thread {
             started.countDown()
             try {
+                val batchTransport = transport as? WinnV3BatchTransport
+                val batch = if (batchTransport != null) WinnV3PacketBatch() else null
                 while (running && !closed) {
-                    val frame = transport.readFrame() ?: run {
-                        fail("Winn v3 engine closed the channel")
-                        return@Thread
-                    }
-                    when (frame.opcode) {
-                        // The engine has already validated this against
-                        // winn3/tun's inner-IP rules; what arrives here is a
-                        // DELIVERY, which is the same event RxPackets counts.
-                        WinnFraming.OP_OUTBOUND ->
-                            seam.writeIncomingPacket(frame.payload, frame.payload.size)
-                        WinnFraming.OP_STATUS_RESPONSE, WinnFraming.OP_CREATE_ACK -> {
-                            lastStatusJson = frame.payloadAsText()
-                            lastStatusAtMs.set(clockMs())
-                        }
-                        WinnFraming.OP_CLOSE_ACK -> {
-                            closeAcknowledged.countDown()
+                    if (batchTransport != null && batch != null) {
+                        if (batchTransport.readBatch(batch) < 0) {
+                            fail("Winn v3 engine closed the channel")
                             return@Thread
                         }
-                        WinnFraming.OP_ERROR -> {
-                            fail("Winn v3 engine reported: ${frame.payloadAsText().take(300)}")
+                        var index = 0
+                        while (index < batch.count && running && !closed) {
+                            val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
+                            if (batch.opcode(index) == WinnFraming.OP_OUTBOUND && batchedSeam != null) {
+                                var end = index + 1
+                                while (end < batch.count && batch.opcode(end) == WinnFraming.OP_OUTBOUND) end++
+                                batchedSeam.writeIncomingBatch(batch, index, end)
+                                index = end
+                            } else {
+                                if (!handleEngineFrame(batch.opcode(index), batch.bytes,
+                                        batch.offset(index), batch.length(index))) return@Thread
+                                index++
+                            }
+                        }
+                    } else {
+                        val frame = transport.readFrame() ?: run {
+                            fail("Winn v3 engine closed the channel")
                             return@Thread
                         }
-                        else -> {
-                            fail(
-                                "Winn v3 engine sent an unhandled opcode: " +
-                                    WinnFraming.opcodeName(frame.opcode)
-                            )
-                            return@Thread
-                        }
+                        if (!handleEngineFrame(frame.opcode, frame.payload, 0, frame.payload.size)) return@Thread
                     }
                 }
             } catch (e: Exception) {
@@ -237,21 +235,33 @@
 
         inboundPump = Thread {
             started.countDown()
-            val buffer = ByteArray(bufferSizeFor(config.innerMtu))
+            val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
+            val batchTransport = transport as? WinnV3BatchTransport
+            val batch = WinnV3PacketBatch()
+            val buffer = if (batchedSeam == null) ByteArray(bufferSizeFor(config.innerMtu)) else null
             try {
                 while (running && !closed) {
-                    // readOutgoingPacket blocks on the CURRENT device. A
-                    // promotion swaps that device underneath this pump; see
-                    // WinnV3AndroidIpPacketSeam.rebindDevice for why the swap is
-                    // safe from here and why the engine is never told.
-                    val n = seam.readOutgoingPacket(buffer)
+                    val n = if (batchedSeam != null) {
+                        batchedSeam.readOutgoingBatch(batch)
+                    } else {
+                        batch.clear()
+                        val length = seam.readOutgoingPacket(buffer!!)
+                        if (length > buffer.size) throw IOException("Winn tun seam overreported packet length")
+                        if (length > 0) batch.append(WinnFraming.OP_INBOUND, buffer, 0, length)
+                        length
+                    }
                     if (n < 0) {
                         if (running && !closed) fail("Winn v3 tun seam ended")
                         return@Thread
                     }
-                    // A zero-length Inbound is a protocol error on this wire.
-                    if (n == 0) continue
-                    transport.writeFrame(WinnFraming.OP_INBOUND, buffer.copyOf(n))
+                    if (n == 0 || !running || closed) continue
+                    if (batchedSeam != null) {
+                        batchedSeam.writeOutgoingBatchIfCurrent(batch) {
+                            if (running && !closed) writePacketBatch(transport, batchTransport, batch)
+                        }
+                    } else {
+                        writePacketBatch(transport, batchTransport, batch)
+                    }
                 }
             } catch (e: Exception) {
                 // Gate on !closed (not running): a typed errno from this pump is
@@ -268,6 +278,49 @@
         }
 
         started.await(2, TimeUnit.SECONDS)
+    }
+
+    private fun writePacketBatch(
+        transport: WinnEngineTransport,
+        batchTransport: WinnV3BatchTransport?,
+        batch: WinnV3PacketBatch,
+    ) {
+        if (batchTransport != null) {
+            batchTransport.writeBatch(batch)
+        } else {
+            // Compatibility for old transports and test doubles. The Android
+            // stream adapter uses writeBatch and never takes this copying path.
+            for (i in 0 until batch.count) {
+                transport.writeFrame(WinnFraming.OP_INBOUND,
+                    batch.bytes.copyOfRange(batch.offset(i), batch.offset(i) + batch.length(i)))
+            }
+        }
+    }
+
+    private fun handleEngineFrame(opcode: Int, payload: ByteArray, offset: Int, length: Int): Boolean {
+        when (opcode) {
+            WinnFraming.OP_OUTBOUND -> {
+                if (offset == 0 && length == payload.size) seam.writeIncomingPacket(payload, length)
+                else seam.writeIncomingPacket(payload.copyOfRange(offset, offset + length), length)
+            }
+            WinnFraming.OP_STATUS_RESPONSE, WinnFraming.OP_CREATE_ACK -> {
+                lastStatusJson = String(payload, offset, length, Charsets.UTF_8)
+                lastStatusAtMs.set(clockMs())
+            }
+            WinnFraming.OP_CLOSE_ACK -> {
+                closeAcknowledged.countDown()
+                return false
+            }
+            WinnFraming.OP_ERROR -> {
+                fail("Winn v3 engine reported: ${String(payload, offset, length, Charsets.UTF_8).take(300)}")
+                return false
+            }
+            else -> {
+                fail("Winn v3 engine sent an unhandled opcode: " + WinnFraming.opcodeName(opcode))
+                return false
+            }
+        }
+        return true
     }
 
     /**
@@ -419,11 +472,25 @@
             running = false
         }
         val process = engine
+        var closeWriter: Thread? = null
         if (process != null) {
+            // A packet writer can be blocked by a full socket buffer while it
+            // owns the transport lock. Bound the graceful request itself, then
+            // close the channel to wake every blocked writer and reader.
+            closeWriter = Thread {
+                try {
+                    process.transport.writeFrame(WinnFraming.OP_CLOSE, ByteArray(0))
+                } catch (_: Exception) {
+                }
+            }.apply {
+                name = "WinsVPN-WinnV3-Close"
+                isDaemon = true
+                start()
+            }
             try {
-                process.transport.writeFrame(WinnFraming.OP_CLOSE, ByteArray(0))
                 closeAcknowledged.await(CLOSE_ACK_WAIT_MS, TimeUnit.MILLISECONDS)
-            } catch (_: Exception) {
+            } catch (_: InterruptedException) {
+                Thread.currentThread().interrupt()
             }
         }
         // Closing the channel unblocks the outbound pump; closing the seam
@@ -433,6 +500,7 @@
         closeQuietly(underlay)
         engine = null
         underlay = null
+        joinQuietly(closeWriter)
         joinQuietly(outboundPump)
         joinQuietly(inboundPump)
         outboundPump = null
```

### android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
@@ -0,0 +1,228 @@
+package org.winsvpn.app
+
+import java.io.EOFException
+import java.io.FileDescriptor
+import java.io.IOException
+import java.io.InputStream
+import java.io.OutputStream
+
+/** A reusable, bounded slab of complete legacy WNN3 frames, owned by one pump. */
+internal class WinnV3PacketBatch(
+    val packetCapacity: Int = 32,
+    byteCapacity: Int = 128 * 1024,
+) {
+    init {
+        require(packetCapacity in 1..256)
+        require(byteCapacity in WinnFraming.HEADER_BYTES + 1..2 * 1024 * 1024)
+    }
+
+    val bytes = ByteArray(byteCapacity)
+    private val offsets = IntArray(packetCapacity)
+    private val lengths = IntArray(packetCapacity)
+    private val opcodes = IntArray(packetCapacity)
+    var count = 0
+        private set
+    var byteCount = 0
+        private set
+    var generation = -1L
+        internal set
+
+    fun offset(index: Int): Int { require(index in 0 until count); return offsets[index] }
+    fun length(index: Int): Int { require(index in 0 until count); return lengths[index] }
+    fun opcode(index: Int): Int { require(index in 0 until count); return opcodes[index] }
+
+    fun clear() {
+        count = 0
+        byteCount = 0
+        generation = -1L
+    }
+
+    fun canAppend(length: Int): Boolean = length >= 0 && count < packetCapacity &&
+        length <= bytes.size - byteCount - WinnFraming.HEADER_BYTES
+
+    fun append(opcode: Int, source: ByteArray, offset: Int, length: Int) {
+        require(offset >= 0 && length >= 0 && offset <= source.size - length)
+        require(WinnFraming.isKnown(opcode))
+        require(length <= WinnFraming.MAX_PAYLOAD_BYTES)
+        require(!WinnFraming.mustBeEmpty(opcode) || length == 0)
+        require(!WinnFraming.mustBeNonEmpty(opcode) || length > 0)
+        require(canAppend(length)) { "Winn batch capacity exceeded" }
+        val start = byteCount
+        put32(start, WinnFraming.MAGIC)
+        put16(start + 4, WinnFraming.FRAMING_VERSION)
+        put16(start + 6, opcode)
+        put32(start + 8, length)
+        put32(start + 12, 0)
+        val payload = start + WinnFraming.HEADER_BYTES
+        System.arraycopy(source, offset, bytes, payload, length)
+        offsets[count] = payload
+        lengths[count] = length
+        opcodes[count] = opcode
+        count++
+        byteCount = payload + length
+    }
+
+    private fun put16(offset: Int, value: Int) {
+        bytes[offset] = value.toByte()
+        bytes[offset + 1] = (value ushr 8).toByte()
+    }
+
+    private fun put32(offset: Int, value: Int) {
+        put16(offset, value)
+        put16(offset + 2, value ushr 16)
+    }
+}
+
+internal interface WinnV3BatchedIpPacketSeam : WinnV3IpPacketSeam {
+    /** Blocks only for the first packet, then drains the ready prefix. */
+    fun readOutgoingBatch(batch: WinnV3PacketBatch): Int
+
+    /** Serializes the send with rebind so a drained old batch cannot escape later. */
+    fun writeOutgoingBatchIfCurrent(batch: WinnV3PacketBatch, write: () -> Unit): Boolean
+
+    /** Delivers the OUTBOUND prefix [start, end) without allocating payload arrays. */
+    fun writeIncomingBatch(batch: WinnV3PacketBatch, start: Int, end: Int)
+}
+
+internal interface WinnV3SliceTunDevice : WinnV3TunDevice {
+    fun write(packet: ByteArray, offset: Int, length: Int)
+}
+
+internal interface WinnV3BatchTransport : WinnEngineTransport {
+    fun writeBatch(batch: WinnV3PacketBatch)
+    fun readBatch(batch: WinnV3PacketBatch): Int
+}
+
+/**
+ * Stream adapter for the existing 16-byte WNN3 header, including its 4-byte
+ * little-endian payload length. Batching concatenates ordinary frames; it
+ * adds no opcode or packet envelope. The callbacks retain platform ownership
+ * of descriptor handoff, read timeout and socket shutdown.
+ *
+ * One reader owns the input slab. All writers, including descriptor handoff,
+ * share a lock. A batch is one OutputStream.write plus one flush under that
+ * lock. Close never waits for the write lock: closing the platform socket must
+ * unblock a writer stalled by bounded kernel backpressure.
+ */
+internal class WinnV3FramedStreamTransport(
+    private val input: InputStream,
+    private val output: OutputStream,
+    private val descriptorSender: (FileDescriptor) -> Unit,
+    private val timeoutSetter: (Int) -> Unit,
+    private val socketCloser: () -> Unit,
+) : WinnV3BatchTransport {
+    private val writeLock = Any()
+    private val singleWrite = WinnV3PacketBatch(1, WinnFraming.MAX_PAYLOAD_BYTES + WinnFraming.HEADER_BYTES)
+    private val singleRead = WinnV3PacketBatch(1, WinnFraming.MAX_PAYLOAD_BYTES + WinnFraming.HEADER_BYTES)
+    private val pending = ByteArray(128 * 1024)
+    private var begin = 0
+    private var end = 0
+    private var readFailure: IOException? = null
+    private var writeFailure: IOException? = null
+    @Volatile private var closed = false
+
+    override fun writeFrame(opcode: Int, payload: ByteArray) {
+        synchronized(writeLock) {
+            singleWrite.clear()
+            singleWrite.append(opcode, payload, 0, payload.size)
+            writeBatch(singleWrite)
+        }
+    }
+
+    override fun writeBatch(batch: WinnV3PacketBatch) {
+        require(batch.count > 0)
+        // Validate the whole batch before the first byte is emitted.
+        for (i in 0 until batch.count) {
+            require(WinnFraming.isHostToEngine(batch.opcode(i))) { "wrong frame direction" }
+        }
+        synchronized(writeLock) {
+            writeFailure?.let { throw it }
+            if (closed) throw IOException("Winn frame stream closed")
+            try {
+                output.write(batch.bytes, 0, batch.byteCount)
+                output.flush()
+            } catch (e: IOException) {
+                // An unknown prefix may have reached the peer. Never retry it.
+                writeFailure = e
+                throw e
+            }
+        }
+    }
+
+    override fun sendDescriptor(fd: FileDescriptor) {
+        synchronized(writeLock) {
+            writeFailure?.let { throw it }
+            if (closed) throw IOException("Winn frame stream closed")
+            try {
+                descriptorSender(fd)
+            } catch (e: IOException) {
+                writeFailure = e
+                throw e
+            }
+        }
+    }
+
+    override fun setReadTimeoutMs(timeoutMs: Int) = timeoutSetter(timeoutMs)
+
+    override fun readFrame(): WinnFrame? {
+        if (readBatch(singleRead) < 0) return null
+        val offset = singleRead.offset(0)
+        return WinnFrame(singleRead.opcode(0), singleRead.bytes.copyOfRange(offset, offset + singleRead.length(0)))
+    }
+
+    override fun readBatch(batch: WinnV3PacketBatch): Int {
+        batch.clear()
+        readFailure?.let { throw it }
+        try {
+            while (batch.count < batch.packetCapacity) {
+                if (closed) throw IOException("Winn frame stream closed")
+                if (end - begin >= WinnFraming.HEADER_BYTES) {
+                    val opcode = WinnFraming.uint16LE(pending, begin + 6)
+                    val length = WinnFraming.uint32LE(pending, begin + 8)
+                    if (WinnFraming.uint32LE(pending, begin) != WinnFraming.MAGIC.toLong() ||
+                        WinnFraming.uint16LE(pending, begin + 4) != WinnFraming.FRAMING_VERSION ||
+                        WinnFraming.uint32LE(pending, begin + 12) != 0L ||
+                        !WinnFraming.isEngineToHost(opcode) ||
+                        length > WinnFraming.MAX_PAYLOAD_BYTES ||
+                        (WinnFraming.mustBeEmpty(opcode) && length != 0L) ||
+                        (WinnFraming.mustBeNonEmpty(opcode) && length == 0L)
+                    ) throw IOException("Invalid Winn frame header")
+                    val n = length.toInt()
+                    if (!batch.canAppend(n)) {
+                        if (batch.count == 0) throw IOException("Winn batch buffer too small for frame")
+                        return batch.count
+                    }
+                    if (end - begin >= WinnFraming.HEADER_BYTES + n) {
+                        batch.append(opcode, pending, begin + WinnFraming.HEADER_BYTES, n)
+                        begin += WinnFraming.HEADER_BYTES + n
+                        continue
+                    }
+                }
+                // Do not block on the next partial frame after delivering a prefix.
+                if (batch.count > 0) return batch.count
+                if (begin != 0) {
+                    System.arraycopy(pending, begin, pending, 0, end - begin)
+                    end -= begin
+                    begin = 0
+                }
+                val n = input.read(pending, end, pending.size - end)
+                if (n < 0) {
+                    if (end != 0) throw EOFException("Winn stream ended inside a frame")
+                    return -1
+                }
+                if (n == 0) throw IOException("Winn stream read made no progress")
+                end += n
+            }
+            return batch.count
+        } catch (e: IOException) {
+            batch.clear()
+            readFailure = e
+            throw e
+        }
+    }
+
+    override fun close() {
+        closed = true
+        socketCloser()
+    }
+}
```

### android/app/src/test/kotlin/org/winsvpn/app/WinnV3AndroidTunBatchTest.kt

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/android/app/src/test/kotlin/org/winsvpn/app/WinnV3AndroidTunBatchTest.kt
@@ -0,0 +1,268 @@
+package org.winsvpn.app
+
+import java.io.IOException
+import java.util.concurrent.CountDownLatch
+import java.util.concurrent.Executors
+import java.util.concurrent.TimeUnit
+import java.util.concurrent.atomic.AtomicBoolean
+import java.util.concurrent.atomic.AtomicInteger
+import org.junit.Assert.*
+import org.junit.Test
+
+class WinnV3AndroidTunBatchTest {
+    @Test fun `bounded slots drain in order and reuse across wraparound`() {
+        val device = HoldingDevice()
+        WinnV3AndroidIpPacketSeam(device, queueDepth = 4).use { seam ->
+            val b = WinnV3PacketBatch(3, 256)
+            repeat(1000) { turn ->
+                repeat(4) { assertTrue(seam.injectOutgoingPacket(byteArrayOf(turn.toByte(), it.toByte()), 2)) }
+                assertFalse(seam.injectOutgoingPacket(byteArrayOf(9), 1))
+                assertEquals(3, seam.readOutgoingBatch(b))
+                repeat(3) { assertEquals(it.toByte(), b.bytes[b.offset(it) + 1]) }
+                assertEquals(1, seam.readOutgoingBatch(b))
+                assertArrayEquals(byteArrayOf(turn.toByte(), 3), b.bytes.copyOfRange(b.offset(0), b.offset(0) + 2))
+            }
+            assertEquals(1000, seam.droppedCount())
+        }
+    }
+
+    @Test fun `short scalar destination errors and retains the whole packet`() {
+        WinnV3AndroidIpPacketSeam(HoldingDevice()).use { seam ->
+            val packet = byteArrayOf(1, 2, 3, 4)
+            assertTrue(seam.injectOutgoingPacket(packet, 4))
+            assertThrows(IOException::class.java) { seam.readOutgoingPacket(ByteArray(3)) }
+            val destination = ByteArray(4)
+            assertEquals(4, seam.readOutgoingPacket(destination))
+            assertArrayEquals(packet, destination)
+        }
+    }
+
+    @Test fun `short batch destination errors and retains the whole packet`() {
+        WinnV3AndroidIpPacketSeam(HoldingDevice()).use { seam ->
+            seam.injectOutgoingPacket(ByteArray(10) { 5 }, 10)
+            assertThrows(IOException::class.java) { seam.readOutgoingBatch(WinnV3PacketBatch(1, 20)) }
+            val b = WinnV3PacketBatch()
+            assertEquals(1, seam.readOutgoingBatch(b))
+            assertEquals(10, b.length(0))
+        }
+    }
+
+    @Test fun `invalid injected lengths never allocate padded or partial packets`() {
+        WinnV3AndroidIpPacketSeam(HoldingDevice()).use { seam ->
+            for (n in listOf(-1, 0, 5, Int.MAX_VALUE)) {
+                assertThrows(IllegalArgumentException::class.java) { seam.injectOutgoingPacket(ByteArray(4), n) }
+            }
+            assertTrue(seam.injectOutgoingPacket(byteArrayOf(7), 1))
+            val b = ByteArray(10)
+            assertEquals(1, seam.readOutgoingPacket(b))
+            assertEquals(7.toByte(), b[0])
+        }
+    }
+
+    @Test fun `rebind invalidates queued and already drained old packets`() {
+        val old = HoldingDevice()
+        WinnV3AndroidIpPacketSeam(old).use { seam ->
+            seam.injectOutgoingPacket(byteArrayOf(1), 1)
+            val stale = WinnV3PacketBatch()
+            assertEquals(1, seam.readOutgoingBatch(stale))
+            seam.injectOutgoingPacket(byteArrayOf(2), 1)
+            seam.rebindDevice(HoldingDevice())
+            assertTrue(old.closed.get())
+            var writes = 0
+            assertFalse(seam.writeOutgoingBatchIfCurrent(stale) { writes++ })
+            seam.injectOutgoingPacket(byteArrayOf(3), 1)
+            val live = WinnV3PacketBatch()
+            assertEquals(1, seam.readOutgoingBatch(live))
+            assertEquals(3.toByte(), live.bytes[live.offset(0)])
+            assertTrue(seam.writeOutgoingBatchIfCurrent(live) { writes++ })
+            assertEquals(1, writes)
+        }
+    }
+
+    @Test fun `old device completing its blocked read after rebind cannot enqueue`() {
+        val old = LateDevice()
+        WinnV3AndroidIpPacketSeam(old).use { seam ->
+            assertTrue(old.started.await(1, TimeUnit.SECONDS))
+            seam.rebindDevice(HoldingDevice())
+            old.release.countDown()
+            assertTrue(old.finished.await(1, TimeUnit.SECONDS))
+            // Drain only after the retired reader's post-read gate has executed.
+            old.thread!!.join(1000)
+            assertFalse(old.thread!!.isAlive)
+            seam.injectOutgoingPacket(byteArrayOf(8), 1)
+            val b = WinnV3PacketBatch()
+            assertEquals(1, seam.readOutgoingBatch(b))
+            assertEquals(8.toByte(), b.bytes[b.offset(0)])
+        }
+    }
+
+    @Test fun `rebind serializes with active batch then rejects retired generation`() {
+        val seam = WinnV3AndroidIpPacketSeam(HoldingDevice())
+        val pool = Executors.newFixedThreadPool(2)
+        val release = CountDownLatch(1)
+        try {
+            seam.injectOutgoingPacket(byteArrayOf(1), 1)
+            val batch = WinnV3PacketBatch()
+            seam.readOutgoingBatch(batch)
+            val entered = CountDownLatch(1)
+            val sending = pool.submit<Boolean> { seam.writeOutgoingBatchIfCurrent(batch) { entered.countDown(); release.await() } }
+            assertTrue(entered.await(1, TimeUnit.SECONDS))
+            val replacing = pool.submit { seam.rebindDevice(HoldingDevice()) }
+            assertThrows(java.util.concurrent.TimeoutException::class.java) { replacing.get(50, TimeUnit.MILLISECONDS) }
+            release.countDown()
+            assertTrue(sending.get(1, TimeUnit.SECONDS))
+            replacing.get(1, TimeUnit.SECONDS)
+            assertFalse(seam.writeOutgoingBatchIfCurrent(batch) { fail("stale send") })
+        } finally { release.countDown(); seam.close(); pool.shutdownNow() }
+    }
+
+    @Test fun `incoming delivery progresses while outgoing channel is backpressured`() {
+        val seam = WinnV3AndroidIpPacketSeam(HoldingDevice())
+        val pool = Executors.newFixedThreadPool(2)
+        val release = CountDownLatch(1)
+        try {
+            seam.injectOutgoingPacket(byteArrayOf(1), 1)
+            val batch = WinnV3PacketBatch()
+            seam.readOutgoingBatch(batch)
+            val entered = CountDownLatch(1)
+            val sending = pool.submit<Boolean> {
+                seam.writeOutgoingBatchIfCurrent(batch) { entered.countDown(); release.await() }
+            }
+            assertTrue(entered.await(1, TimeUnit.SECONDS))
+            pool.submit { seam.writeIncomingPacket(byteArrayOf(9), 1) }.get(1, TimeUnit.SECONDS)
+            release.countDown()
+            assertTrue(sending.get(1, TimeUnit.SECONDS))
+        } finally { release.countDown(); seam.close(); pool.shutdownNow() }
+    }
+
+    @Test fun `same device rebind does not create another physical reader`() {
+        val d = HoldingDevice()
+        WinnV3AndroidIpPacketSeam(d).use { seam ->
+            assertTrue(d.started.await(1, TimeUnit.SECONDS))
+            seam.rebindDevice(d)
+            assertEquals(1, d.reads.get())
+            assertFalse(d.closed.get())
+        }
+    }
+
+    @Test fun `close wakes empty scalar and batch consumers with a stuck old read`() {
+        for (batchMode in listOf(false, true)) {
+            val d = LateDevice()
+            val seam = WinnV3AndroidIpPacketSeam(d)
+            val pool = Executors.newSingleThreadExecutor()
+            try {
+                assertTrue(d.started.await(1, TimeUnit.SECONDS))
+                val reading = pool.submit<Int> {
+                    if (batchMode) seam.readOutgoingBatch(WinnV3PacketBatch()) else seam.readOutgoingPacket(ByteArray(100))
+                }
+                seam.close()
+                assertEquals(-1, reading.get(1, TimeUnit.SECONDS).toInt())
+                assertFalse(seam.injectOutgoingPacket(byteArrayOf(1), 1))
+                assertNull(seam.currentDevice())
+                val replacement = HoldingDevice()
+                seam.rebindDevice(replacement)
+                assertTrue(replacement.closed.get())
+            } finally { seam.close(); d.release.countDown(); pool.shutdownNow() }
+        }
+    }
+
+    @Test fun `active read error wakes consumer with original typed throwable`() {
+        val failure = IOException("read failed")
+        val d = object : HoldingDevice() { override fun read(buffer: ByteArray): Int = throw failure }
+        WinnV3AndroidIpPacketSeam(d).use { seam ->
+            val pool = Executors.newSingleThreadExecutor()
+            try {
+                val result = pool.submit<Throwable> {
+                    try { seam.readOutgoingBatch(WinnV3PacketBatch()); AssertionError("accepted") } catch (t: Throwable) { t }
+                }
+                assertSame(failure, result.get(1, TimeUnit.SECONDS))
+            } finally { pool.shutdownNow() }
+        }
+    }
+
+    @Test fun `physical packet above mtu is rejected instead of truncated`() {
+        val d = object : HoldingDevice() {
+            override fun read(buffer: ByteArray): Int {
+                assertTrue(buffer.size > mtu)
+                return mtu + 1
+            }
+        }
+        WinnV3AndroidIpPacketSeam(d).use { seam ->
+            assertThrows(IOException::class.java) { seam.readOutgoingPacket(ByteArray(2000)) }
+        }
+    }
+
+    @Test fun `incoming batch uses source offsets without per packet arrays`() {
+        val arrays = mutableListOf<ByteArray>()
+        val got = mutableListOf<ByteArray>()
+        val d = object : HoldingDevice(), WinnV3SliceTunDevice {
+            override fun write(packet: ByteArray, offset: Int, length: Int) {
+                arrays += packet
+                got += packet.copyOfRange(offset, offset + length)
+            }
+        }
+        WinnV3AndroidIpPacketSeam(d).use { seam ->
+            val b = WinnV3PacketBatch()
+            b.append(WinnFraming.OP_OUTBOUND, byteArrayOf(1, 2), 0, 2)
+            b.append(WinnFraming.OP_OUTBOUND, byteArrayOf(3), 0, 1)
+            seam.writeIncomingBatch(b, 0, 2)
+            assertArrayEquals(byteArrayOf(1, 2), got[0])
+            assertArrayEquals(byteArrayOf(3), got[1])
+            assertSame(b.bytes, arrays[0])
+            assertSame(arrays[0], arrays[1])
+        }
+    }
+
+    @Test fun `invalid incoming batch rejects entire prefix and write errors propagate`() {
+        val writes = AtomicInteger()
+        val failure = IOException("tun write")
+        val d = object : HoldingDevice() {
+            override fun write(packet: ByteArray, length: Int) { writes.incrementAndGet(); throw failure }
+        }
+        WinnV3AndroidIpPacketSeam(d).use { seam ->
+            val b = WinnV3PacketBatch()
+            b.append(WinnFraming.OP_OUTBOUND, byteArrayOf(1), 0, 1)
+            b.append(WinnFraming.OP_STATUS_RESPONSE, byteArrayOf(2), 0, 1)
+            assertThrows(IOException::class.java) { seam.writeIncomingBatch(b, 0, 2) }
+            assertEquals(0, writes.get())
+            assertSame(failure, assertThrows(IOException::class.java) { seam.writeIncomingBatch(b, 0, 1) })
+        }
+    }
+
+    @Test fun `larger rebind mtu refuses before replacing live device`() {
+        val d = HoldingDevice()
+        WinnV3AndroidIpPacketSeam(d).use { seam ->
+            val replacement = object : HoldingDevice() { override val mtu = 2000 }
+            assertThrows(IllegalArgumentException::class.java) { seam.rebindDevice(replacement) }
+            assertSame(d, seam.currentDevice())
+            assertFalse(d.closed.get())
+            replacement.close()
+        }
+    }
+
+    private open class HoldingDevice : WinnV3TunDevice {
+        override val mtu = 1359
+        val started = CountDownLatch(1)
+        val reads = AtomicInteger()
+        val closed = AtomicBoolean()
+        private val gate = CountDownLatch(1)
+        override fun read(buffer: ByteArray): Int { reads.incrementAndGet(); started.countDown(); gate.await(); return -1 }
+        override fun write(packet: ByteArray, length: Int) = Unit
+        override fun close() { closed.set(true); gate.countDown() }
+    }
+
+    private class LateDevice : HoldingDevice() {
+        val release = CountDownLatch(1)
+        val finished = CountDownLatch(1)
+        @Volatile var thread: Thread? = null
+        override fun read(buffer: ByteArray): Int {
+            thread = Thread.currentThread()
+            started.countDown()
+            release.await()
+            buffer[0] = 99
+            finished.countDown()
+            return 1
+        }
+        override fun close() { closed.set(true) }
+    }
+}
```

### android/app/src/test/kotlin/org/winsvpn/app/WinnV3BridgeBatchTest.kt

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/android/app/src/test/kotlin/org/winsvpn/app/WinnV3BridgeBatchTest.kt
@@ -0,0 +1,152 @@
+package org.winsvpn.app
+
+import java.io.ByteArrayInputStream
+import java.io.ByteArrayOutputStream
+import java.io.FileDescriptor
+import java.io.IOException
+import java.io.InputStream
+import java.io.OutputStream
+import java.util.concurrent.CopyOnWriteArrayList
+import java.util.concurrent.CountDownLatch
+import java.util.concurrent.Executors
+import java.util.concurrent.TimeUnit
+import java.util.concurrent.atomic.AtomicInteger
+import org.junit.Assert.*
+import org.junit.Test
+
+class WinnV3BridgeBatchTest {
+    @Test fun `compiled production local socket adapter exposes batch transport`() {
+        val adapter = Class.forName("org.winsvpn.app.WinnAndroidEngineHost\$LocalSocketWinnTransport")
+        assertTrue(WinnV3BatchTransport::class.java.isAssignableFrom(adapter))
+    }
+
+    @Test fun `bridge drains a ready burst in batches and interoperates with legacy frame reader`() {
+        val (client, peer) = WinnEngineDouble.connectedPair()
+        val engine = WinnEngineDouble(peer)
+        val calls = AtomicInteger()
+        val raw = WinnV3FramedStreamTransport(client.getInputStream(), client.getOutputStream(), {},
+            { client.soTimeout = it }, { client.close() })
+        val transport = object : WinnV3BatchTransport by raw {
+            override fun writeBatch(batch: WinnV3PacketBatch) { calls.incrementAndGet(); raw.writeBatch(batch) }
+        }
+        val device = TestDevice()
+        val seam = WinnV3AndroidIpPacketSeam(device)
+        repeat(64) { seam.injectOutgoingPacket(byteArrayOf(it.toByte(), 7), 2) }
+        val bridge = bridge(transport, seam)
+        try {
+            engine.start()
+            bridge.start()
+            await { engine.receivedInbound.size == 64 && device.received.size == 64 }
+            assertEquals(2, calls.get())
+            repeat(64) {
+                assertArrayEquals(byteArrayOf(it.toByte(), 7), engine.receivedInbound[it])
+                assertArrayEquals(engine.receivedInbound[it], device.received[it])
+            }
+            bridge.requestStatus()
+            await { engine.statusRequests.get() == 1 }
+            assertNull(bridge.failure())
+        } finally { bridge.close(); engine.close(); client.close(); peer.close() }
+    }
+
+    @Test fun `control boundary stops delivery before later packet in same read batch`() {
+        val bytes = ByteArrayOutputStream()
+        WinnFraming.writeFrame(bytes, WinnFraming.OP_CREATE_ACK, "{}".toByteArray())
+        WinnFraming.writeFrame(bytes, WinnFraming.OP_OUTBOUND, byteArrayOf(1))
+        WinnFraming.writeFrame(bytes, WinnFraming.OP_STATUS_RESPONSE, "status-before-error".toByteArray())
+        WinnFraming.writeFrame(bytes, WinnFraming.OP_OUTBOUND, byteArrayOf(2))
+        WinnFraming.writeFrame(bytes, WinnFraming.OP_ERROR, "terminal".toByteArray())
+        WinnFraming.writeFrame(bytes, WinnFraming.OP_OUTBOUND, byteArrayOf(3))
+        val raw = WinnV3FramedStreamTransport(ByteArrayInputStream(bytes.toByteArray()), ByteArrayOutputStream(), {}, {}, {})
+        val device = TestDevice()
+        val bridge = bridge(raw, WinnV3AndroidIpPacketSeam(device))
+        try {
+            bridge.start()
+            await { bridge.failure() != null }
+            assertEquals("status-before-error", bridge.statusJson())
+            assertEquals(2, device.received.size)
+            assertArrayEquals(byteArrayOf(1), device.received[0])
+            assertArrayEquals(byteArrayOf(2), device.received[1])
+        } finally { bridge.close() }
+    }
+
+    @Test fun `close is bounded when packet writer owns stream lock under backpressure`() {
+        val closed = CountDownLatch(1)
+        val writing = CountDownLatch(1)
+        val ack = ByteArrayOutputStream().also { WinnFraming.writeFrame(it, WinnFraming.OP_CREATE_ACK, "{}".toByteArray()) }.toByteArray()
+        val input = object : InputStream() {
+            val initial = ByteArrayInputStream(ack)
+            override fun read(): Int = throw AssertionError("scalar read")
+            override fun read(b: ByteArray, off: Int, len: Int): Int {
+                if (initial.available() > 0) return initial.read(b, off, len)
+                closed.await()
+                throw IOException("closed")
+            }
+        }
+        val output = object : OutputStream() {
+            override fun write(b: Int) = Unit
+            override fun write(b: ByteArray, off: Int, len: Int) {
+                if (WinnFraming.uint16LE(b, off + 6) == WinnFraming.OP_INBOUND) {
+                    writing.countDown()
+                    closed.await()
+                    throw IOException("closed while blocked")
+                }
+            }
+        }
+        val raw = WinnV3FramedStreamTransport(input, output, {}, {}, { closed.countDown() })
+        val seam = WinnV3AndroidIpPacketSeam(TestDevice())
+        seam.injectOutgoingPacket(byteArrayOf(1), 1)
+        val bridge = bridge(raw, seam)
+        val pool = Executors.newSingleThreadExecutor()
+        try {
+            bridge.start()
+            assertTrue(writing.await(2, TimeUnit.SECONDS))
+            pool.submit { bridge.close() }.get(3, TimeUnit.SECONDS)
+            assertEquals(0, closed.count)
+            assertFalse(bridge.isRunning())
+            assertNull(seam.currentDevice())
+        } finally { closed.countDown(); bridge.close(); pool.shutdownNow() }
+    }
+
+    private fun bridge(transport: WinnEngineTransport, seam: WinnV3IpPacketSeam): WinnV3Bridge {
+        val process = object : WinnEngineProcess {
+            override val transport = transport
+            override fun isAlive() = true
+            override fun describe() = "JVM framing fixture"
+            override fun close() = transport.close()
+        }
+        val host = object : WinnEngineHost {
+            override fun openProtectedUnderlaySocket() = object : WinnUnderlaySocket {
+                override val descriptor = FileDescriptor()
+                override val protectedBeforeHandoff = true
+                override val localPort = 40404
+                override fun close() = Unit
+            }
+            override fun startEngineProcess() = process
+            override fun openAwgDatagramSeam(): WinnAwgDatagramSeam? = null
+            override fun onDebug(message: String) = Unit
+            override fun onWarning(message: String, error: Throwable?) = Unit
+            override fun onError(message: String, error: Throwable?) = Unit
+        }
+        return WinnV3Bridge(host, seam, WinnV3EngineConfig(
+            gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3", innerNextHop = "10.8.1.1",
+            innerMtu = 1359, pathMtu = 1500, carrierClasses = listOf("udp", "tcp", "tls"), sessionId = "batch-test",
+        ))
+    }
+
+    private fun await(predicate: () -> Boolean) {
+        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
+        while (!predicate()) {
+            if (System.nanoTime() > deadline) fail("condition did not complete")
+            Thread.sleep(5)
+        }
+    }
+
+    private class TestDevice : WinnV3TunDevice {
+        override val mtu = 1359
+        private val done = CountDownLatch(1)
+        val received = CopyOnWriteArrayList<ByteArray>()
+        override fun read(buffer: ByteArray): Int { done.await(); return -1 }
+        override fun write(packet: ByteArray, length: Int) { received += packet.copyOf(length) }
+        override fun close() { done.countDown() }
+    }
+}
```

### android/app/src/test/kotlin/org/winsvpn/app/WinnV3PacketBatchTest.kt

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/android/app/src/test/kotlin/org/winsvpn/app/WinnV3PacketBatchTest.kt
@@ -0,0 +1,275 @@
+package org.winsvpn.app
+
+import java.io.ByteArrayInputStream
+import java.io.ByteArrayOutputStream
+import java.io.EOFException
+import java.io.IOException
+import java.io.InputStream
+import java.io.OutputStream
+import java.net.ServerSocket
+import java.net.Socket
+import java.util.concurrent.CountDownLatch
+import java.util.concurrent.Executors
+import java.util.concurrent.TimeUnit
+import java.util.concurrent.atomic.AtomicInteger
+import org.junit.Assert.*
+import org.junit.Test
+
+class WinnV3PacketBatchTest {
+    private fun transport(input: InputStream, output: OutputStream = ByteArrayOutputStream()) =
+        WinnV3FramedStreamTransport(input, output, {}, {}, { input.close(); output.close() })
+
+    private fun wire(opcode: Int, vararg payloads: ByteArray): ByteArray {
+        val out = ByteArrayOutputStream()
+        for (payload in payloads) WinnFraming.writeFrame(out, opcode, payload)
+        return out.toByteArray()
+    }
+
+    @Test fun `batch is byte exact legacy framing and one write plus flush`() {
+        val output = CountingOutput()
+        val t = transport(ByteArrayInputStream(byteArrayOf()), output)
+        val batch = WinnV3PacketBatch()
+        val expected = ByteArrayOutputStream()
+        repeat(32) {
+            val packet = ByteArray(1359) { b -> (it + b).toByte() }
+            batch.append(WinnFraming.OP_INBOUND, packet, 0, packet.size)
+            WinnFraming.writeFrame(expected, WinnFraming.OP_INBOUND, packet)
+        }
+        t.writeBatch(batch)
+        assertArrayEquals(expected.toByteArray(), output.toByteArray())
+        assertEquals(1, output.writes)
+        assertEquals(1, output.flushes)
+        val reader = WinnFrameReader(ByteArrayInputStream(output.toByteArray()), false)
+        repeat(32) { assertEquals(1359, reader.read()!!.payload.size) }
+        assertNull(reader.read())
+    }
+
+    @Test fun `all packet slab storage is reused over many wraps`() {
+        val b = WinnV3PacketBatch(2, 128)
+        val bytes = b.bytes
+        repeat(10000) {
+            b.clear()
+            b.append(WinnFraming.OP_INBOUND, byteArrayOf(it.toByte()), 0, 1)
+            assertSame(bytes, b.bytes)
+            assertEquals(it.toByte(), b.bytes[b.offset(0)])
+        }
+    }
+
+    @Test fun `batch rejects invalid slice and limits before mutation`() {
+        val b = WinnV3PacketBatch(1, 20)
+        assertThrows(IllegalArgumentException::class.java) { b.append(WinnFraming.OP_INBOUND, ByteArray(5), 0, 5) }
+        assertThrows(IllegalArgumentException::class.java) { b.append(WinnFraming.OP_INBOUND, ByteArray(4), Int.MAX_VALUE, 4) }
+        assertThrows(IllegalArgumentException::class.java) { b.append(WinnFraming.OP_INBOUND, ByteArray(0), 0, 0) }
+        assertEquals(0, b.count)
+        b.append(WinnFraming.OP_INBOUND, ByteArray(4), 0, 4)
+        assertThrows(IllegalArgumentException::class.java) { b.append(WinnFraming.OP_INBOUND, ByteArray(1), 0, 1) }
+        assertEquals(1, b.count)
+    }
+
+    @Test fun `fragmentation at every chunk size retains packets and control order`() {
+        val data = wire(WinnFraming.OP_OUTBOUND, ByteArray(1400) { it.toByte() }, byteArrayOf(4, 5)) +
+            wire(WinnFraming.OP_STATUS_RESPONSE, "status".toByteArray()) + wire(WinnFraming.OP_CLOSE_ACK, ByteArray(0))
+        for (chunk in listOf(1, 2, 3, 4, 7, 15, 16, 17, 99, 1407, data.size)) {
+            val input = object : ByteArrayInputStream(data) {
+                override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(chunk, len))
+            }
+            val t = transport(input)
+            val b = WinnV3PacketBatch()
+            val got = mutableListOf<WinnFrame>()
+            while (t.readBatch(b) >= 0) {
+                for (i in 0 until b.count) got += WinnFrame(b.opcode(i), b.bytes.copyOfRange(b.offset(i), b.offset(i) + b.length(i)))
+            }
+            assertEquals("chunk=$chunk", 4, got.size)
+            assertArrayEquals(ByteArray(1400) { it.toByte() }, got[0].payload)
+            assertArrayEquals(byteArrayOf(4, 5), got[1].payload)
+            assertEquals("status", got[2].payloadAsText())
+            assertEquals(WinnFraming.OP_CLOSE_ACK, got[3].opcode)
+        }
+    }
+
+    @Test fun `burst is read in one source call and caller capacity leaves next frame queued`() {
+        val data = wire(WinnFraming.OP_OUTBOUND, *Array(40) { byteArrayOf(it.toByte()) })
+        var reads = 0
+        val t = transport(object : ByteArrayInputStream(data) {
+            override fun read(b: ByteArray, off: Int, len: Int): Int { reads++; return super.read(b, off, len) }
+        })
+        val b = WinnV3PacketBatch()
+        assertEquals(32, t.readBatch(b))
+        assertEquals(8, t.readBatch(b))
+        assertEquals(32.toByte(), b.bytes[b.offset(0)])
+        assertEquals(1, reads)
+        assertEquals(-1, t.readBatch(b))
+    }
+
+    @Test fun `complete prefix returns before blocking on partial next frame`() {
+        val first = wire(WinnFraming.OP_OUTBOUND, byteArrayOf(9))
+        val tail = wire(WinnFraming.OP_OUTBOUND, byteArrayOf(8)).copyOf(10)
+        var calls = 0
+        val t = transport(object : InputStream() {
+            override fun read(): Int = throw AssertionError("scalar read")
+            override fun read(b: ByteArray, off: Int, len: Int): Int {
+                if (calls++ > 0) throw AssertionError("blocked for a partial second frame")
+                val data = first + tail
+                System.arraycopy(data, 0, b, off, data.size)
+                return data.size
+            }
+        })
+        assertEquals(1, t.readBatch(WinnV3PacketBatch()))
+        assertEquals(1, calls)
+    }
+
+    @Test fun `every truncated header or payload fails and latches without resync`() {
+        val data = wire(WinnFraming.OP_OUTBOUND, ByteArray(40) { 7 })
+        for (cut in 1 until data.size) {
+            val t = transport(ByteArrayInputStream(data.copyOf(cut)))
+            val b = WinnV3PacketBatch()
+            val first = assertThrows(EOFException::class.java) { t.readBatch(b) }
+            assertSame(first, assertThrows(EOFException::class.java) { t.readBatch(b) })
+            assertEquals(0, b.count)
+        }
+        assertEquals(-1, transport(ByteArrayInputStream(byteArrayOf())).readBatch(WinnV3PacketBatch()))
+    }
+
+    @Test fun `malformed header direction empty packet and oversized length fail closed`() {
+        val valid = wire(WinnFraming.OP_OUTBOUND, byteArrayOf(8))
+        for ((index, value) in listOf(0 to 0, 4 to 2, 12 to 1, 6 to WinnFraming.OP_INBOUND, 8 to 0, 11 to 127)) {
+            val bad = valid.clone()
+            bad[index] = value.toByte()
+            val t = transport(ByteArrayInputStream(bad + valid))
+            val b = WinnV3PacketBatch()
+            val failure = assertThrows(IOException::class.java) { t.readBatch(b) }
+            assertSame(failure, assertThrows(IOException::class.java) { t.readBatch(b) })
+            assertEquals(0, b.count)
+        }
+    }
+
+    @Test fun `zero progress read fails without spinning`() {
+        val t = transport(object : InputStream() {
+            override fun read(): Int = 0
+            override fun read(b: ByteArray, off: Int, len: Int): Int = 0
+        })
+        assertThrows(IOException::class.java) { t.readBatch(WinnV3PacketBatch()) }
+    }
+
+    @Test fun `too small batch fails without delivering a truncated packet`() {
+        val t = transport(ByteArrayInputStream(wire(WinnFraming.OP_OUTBOUND, ByteArray(50))))
+        assertThrows(IOException::class.java) { t.readBatch(WinnV3PacketBatch(1, 20)) }
+    }
+
+    @Test fun `maximum length packet crosses pending slab and frame boundaries`() {
+        val payload = ByteArray(WinnFraming.MAX_PAYLOAD_BYTES) { it.toByte() }
+        val t = transport(ByteArrayInputStream(wire(WinnFraming.OP_OUTBOUND, payload, payload, payload)))
+        val b = WinnV3PacketBatch()
+        repeat(3) {
+            assertEquals(1, t.readBatch(b))
+            assertEquals(payload.size, b.length(0))
+            assertArrayEquals(payload, b.bytes.copyOfRange(b.offset(0), b.offset(0) + b.length(0)))
+        }
+        assertEquals(-1, t.readBatch(b))
+    }
+
+    @Test fun `partial output failure poisons future writes and never retries prefix`() {
+        val writes = AtomicInteger()
+        val failure = IOException("partial write")
+        val t = transport(ByteArrayInputStream(byteArrayOf()), object : OutputStream() {
+            override fun write(value: Int) = Unit
+            override fun write(b: ByteArray, off: Int, len: Int) { writes.incrementAndGet(); throw failure }
+        })
+        assertSame(failure, assertThrows(IOException::class.java) { t.writeFrame(WinnFraming.OP_INBOUND, byteArrayOf(1)) })
+        assertSame(failure, assertThrows(IOException::class.java) { t.writeFrame(WinnFraming.OP_STATUS_REQUEST, byteArrayOf()) })
+        assertEquals(1, writes.get())
+    }
+
+    @Test fun `wrong direction anywhere rejects whole batch before output`() {
+        val output = CountingOutput()
+        val b = WinnV3PacketBatch()
+        b.append(WinnFraming.OP_INBOUND, byteArrayOf(1), 0, 1)
+        b.append(WinnFraming.OP_OUTBOUND, byteArrayOf(2), 0, 1)
+        assertThrows(IllegalArgumentException::class.java) { transport(ByteArrayInputStream(byteArrayOf()), output).writeBatch(b) }
+        assertEquals(0, output.writes)
+    }
+
+    @Test fun `concurrent control and packet writes never interleave within a batch`() {
+        val out = CountingOutput()
+        val t = transport(ByteArrayInputStream(byteArrayOf()), out)
+        val pool = Executors.newFixedThreadPool(5)
+        try {
+            val jobs = (0 until 4).map { worker -> pool.submit {
+                val b = WinnV3PacketBatch()
+                repeat(100) {
+                    b.clear()
+                    repeat(8) { index -> b.append(WinnFraming.OP_INBOUND, byteArrayOf(worker.toByte(), index.toByte()), 0, 2) }
+                    t.writeBatch(b)
+                }
+            } } + pool.submit { repeat(100) { t.writeFrame(WinnFraming.OP_STATUS_REQUEST, byteArrayOf()) } }
+            jobs.forEach { it.get(5, TimeUnit.SECONDS) }
+            val r = WinnFrameReader(ByteArrayInputStream(out.toByteArray()), false)
+            var packets = 0
+            var controls = 0
+            while (true) {
+                val frame = r.read() ?: break
+                if (frame.opcode == WinnFraming.OP_STATUS_REQUEST) { controls++; continue }
+                assertEquals(0.toByte(), frame.payload[1])
+                val worker = frame.payload[0]
+                repeat(7) { index ->
+                    val next = r.read()!!
+                    assertEquals(WinnFraming.OP_INBOUND, next.opcode)
+                    assertArrayEquals(byteArrayOf(worker, (index + 1).toByte()), next.payload)
+                }
+                packets += 8
+            }
+            assertEquals(3200, packets)
+            assertEquals(100, controls)
+            assertEquals(500, out.writes)
+        } finally { pool.shutdownNow() }
+    }
+
+    @Test fun `descriptor callback and frame bytes share the same writer lock`() {
+        val output = CountingOutput()
+        val entered = CountDownLatch(1)
+        val release = CountDownLatch(1)
+        val t = WinnV3FramedStreamTransport(ByteArrayInputStream(byteArrayOf()), output,
+            { entered.countDown(); release.await(); output.write(byteArrayOf(0)); output.flush() }, {}, {})
+        val pool = Executors.newFixedThreadPool(2)
+        try {
+            val descriptor = pool.submit { t.sendDescriptor(java.io.FileDescriptor()) }
+            assertTrue(entered.await(1, TimeUnit.SECONDS))
+            val frame = pool.submit { t.writeFrame(WinnFraming.OP_STATUS_REQUEST, byteArrayOf()) }
+            assertThrows(java.util.concurrent.TimeoutException::class.java) { frame.get(50, TimeUnit.MILLISECONDS) }
+            assertEquals(0, output.size())
+            release.countDown()
+            descriptor.get(1, TimeUnit.SECONDS)
+            frame.get(1, TimeUnit.SECONDS)
+            assertArrayEquals(byteArrayOf(0) + wire(WinnFraming.OP_STATUS_REQUEST, byteArrayOf()), output.toByteArray())
+        } finally { release.countDown(); pool.shutdownNow() }
+    }
+
+    @Test fun `close interrupts blocked stream reader without acquiring write lock`() {
+        ServerSocket(0).use { server ->
+            Socket("127.0.0.1", server.localPort).use { client ->
+                server.accept().use { peer ->
+                    val t = WinnV3FramedStreamTransport(client.getInputStream(), client.getOutputStream(), {}, {}, { client.close() })
+                    val pool = Executors.newSingleThreadExecutor()
+                    try {
+                        val entered = CountDownLatch(1)
+                        val read = pool.submit<Boolean> {
+                            entered.countDown()
+                            try { t.readBatch(WinnV3PacketBatch()); false } catch (_: IOException) { true }
+                        }
+                        assertTrue(entered.await(1, TimeUnit.SECONDS))
+                        t.close()
+                        assertTrue(read.get(2, TimeUnit.SECONDS))
+                        assertFalse(peer.isClosed)
+                    } finally { pool.shutdownNow() }
+                }
+            }
+        }
+    }
+
+    private class CountingOutput : ByteArrayOutputStream() {
+        var writes = 0
+        var flushes = 0
+        override fun write(b: ByteArray, off: Int, len: Int) { writes++; super.write(b, off, len) }
+        override fun flush() { flushes++ }
+    }
+}
```

### android/app/src/test/run_winn3_batch_tests.py

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/android/app/src/test/run_winn3_batch_tests.py
@@ -0,0 +1,110 @@
+#!/usr/bin/env python3
+"""Compile actual Kotlin sources against cached Android SDK; run portable JUnit.
+
+No Gradle or Flutter tasks. Output is isolated in a temporary directory. This
+harness exercises JVM logic, not Android descriptor or device acceptance.
+"""
+import argparse
+import json
+import os
+from pathlib import Path
+import re
+import shlex
+import subprocess
+import tempfile
+
+parser = argparse.ArgumentParser()
+parser.add_argument('--java', required=True)
+parser.add_argument('--android-jar', required=True)
+parser.add_argument('--repeat', type=int, default=1)
+args = parser.parse_args()
+root = Path(__file__).resolve().parents[4]
+cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
+pin = json.loads((root / 'tools/toolchain-pins.json').read_text())['tools']['kotlin']['version']
+
+
+def jar(group, artifact, version):
+    matches = list((cache / group / artifact / version).glob(f'*/{artifact}-{version}.jar'))
+    if len(matches) != 1:
+        raise RuntimeError(f'Expected exactly one cached {group}:{artifact}:{version}, found {len(matches)}')
+    return str(matches[0])
+
+
+stdlib = jar('org.jetbrains.kotlin', 'kotlin-stdlib', pin)
+annotations = jar('org.jetbrains', 'annotations', '13.0')
+compiler_cp = os.pathsep.join([
+    jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', pin), stdlib,
+    jar('org.jetbrains.kotlin', 'kotlin-reflect', '1.6.10'),
+    jar('org.jetbrains.kotlin', 'kotlin-daemon-embeddable', pin),
+    jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.8.0'),
+    jar('org.jetbrains.intellij.deps', 'trove4j', '1.0.20200330'), annotations,
+])
+junit = jar('junit', 'junit', '4.13.2')
+hamcrest = jar('org.hamcrest', 'hamcrest-core', '1.3')
+classpath = os.pathsep.join([stdlib, annotations, junit, hamcrest, args.android_jar,
+                            jar('androidx.annotation', 'annotation-jvm', '1.8.1')])
+main = root / 'android/app/src/main/kotlin/org/winsvpn/app'
+tests = root / 'android/app/src/test/kotlin/org/winsvpn/app'
+# Same structural entry-point exclusion as verify_winn3_conformance.sh.
+sources = []
+for source in sorted(main.glob('*.kt')):
+    if source.name.startswith('._'):
+        continue
+    text = source.read_text()
+    if re.search(r'^import (io\.flutter|com\.google|org\.json|org\.amnezia|androidx\.core)', text, re.M):
+        continue
+    if re.search(r'class +[A-Za-z0-9_]+ *: *(Activity|BroadcastReceiver|Service|VpnService|FlutterActivity|WearableListenerService|LauncherEntryActivity)\(', text):
+        continue
+    if re.search(r'^\s*[A-Za-z_].*VpnTunnelService\.', text, re.M):
+        continue
+    sources.append(source)
+for name in ['WinnV3AndroidTun.kt', 'WinnV3Bridge.kt', 'WinnV3PacketBatch.kt', 'WinnAndroidEngineHost.kt']:
+    assert main / name in sources, f'Implementation omitted: {name}'
+test_classes = ['WinnV3PacketBatchTest', 'WinnV3AndroidTunBatchTest', 'WinnV3BridgeBatchTest',
+                'WinnV3BridgeTest', 'WinnProtocolFramingTest', 'WinnV3AdoptionTest', 'WinnTunnelBridgeTest']
+for name in test_classes + ['WinnEngineDouble']:
+    path = tests / (name + '.kt')
+    if not path.is_file():
+        raise RuntimeError(f'Missing required test source: {path}')
+    sources.append(path)
+work = Path(tempfile.mkdtemp(prefix='winn3-android-batch-'))
+fields = set()
+for source in sources:
+    fields.update(re.findall(r'BuildConfig\.([A-Za-z_]+)', source.read_text()))
+config = work / 'BuildConfig.kt'
+config.write_text('package org.winsvpn.app\ninternal object BuildConfig {\n' +
+                  ''.join(f'    const val {field} = ' + ('false' if field == 'DEBUG' else '""') + '\n'
+                          for field in sorted(fields)) + '}\n')
+sources.append(config)
+# The excluded Android service contributes one compile-time constant to the
+# existing adoption tests. Extract its exact source literal, with no substitute
+# service behavior. This does not compile or exercise the Android service.
+sink = re.search(r'const val IPV6_FAIL_CLOSED_SINK = ("[^"\n]+")',
+                 (main / 'VpnTunnelService.kt').read_text())
+assert sink is not None
+service_constant = work / 'ServiceConstant.kt'
+service_constant.write_text('package org.winsvpn.app\ninternal object VpnTunnelService {\n' +
+                            '    const val IPV6_FAIL_CLOSED_SINK = ' + sink.group(1) + '\n}\n')
+sources.append(service_constant)
+classes = work / 'classes'
+command = [args.java, '-cp', compiler_cp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
+           '-no-reflect', '-no-stdlib', '-jvm-target', '17', '-classpath', classpath,
+           '-d', str(classes)] + [str(source) for source in sources]
+(work / 'compile-command.txt').write_text(shlex.join(command) + '\n')
+print(f'WORK_DIR={work}', flush=True)
+print(f'Compile Kotlin {pin}: {len(sources)} source files against {args.android_jar}', flush=True)
+compiled = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
+(work / 'compile.log').write_text(compiled.stdout)
+print(compiled.stdout, end='', flush=True)
+if compiled.returncode:
+    raise SystemExit(compiled.returncode)
+command = [args.java, '-cp', os.pathsep.join([str(classes), classpath]), 'org.junit.runner.JUnitCore'] + [
+    'org.winsvpn.app.' + name for name in test_classes]
+(work / 'test-command.txt').write_text(shlex.join(command) + '\n')
+print('JUnit classes: ' + ', '.join(test_classes), flush=True)
+for iteration in range(args.repeat):
+    result = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
+    (work / f'junit-{iteration + 1}.log').write_text(result.stdout)
+    print(result.stdout, end='', flush=True)
+    if result.returncode:
+        raise SystemExit(result.returncode)
```

### apple/EngineWrappers/WinnTunnel.h

<!-- winn345-patch:diff -->
```diff
--- a/apple/EngineWrappers/WinnTunnel.h
+++ b/apple/EngineWrappers/WinnTunnel.h
@@ -339,6 +339,59 @@
 extern long long WinnTunnelCreateWinn3(char* configJSON, int udpFD,
                                        char** errorOut);
 
+#ifndef WINS_WINN3_PACKET_BATCH_H
+#define WINS_WINN3_PACKET_BATCH_H
+#include <stddef.h>
+#include <stdint.h>
+
+/* Apple 64-bit ABI. All integers are in host byte order. */
+#define WINS_WINN3_BATCH_MAX 32
+#define WINS_WINN3_PACKET_STRIDE 24
+#define WINS_WINN3_PACKET_MAX 65535
+
+typedef struct WinsWinn3PacketDescriptor {
+  void *data;
+  uint32_t length;
+  uint32_t capacity;
+  uint32_t family;
+  uint32_t reserved;
+} WinsWinn3PacketDescriptor;
+
+#if defined(__cplusplus)
+static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
+static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
+#else
+_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
+#endif
+#endif
+
+
+/*
+ * Stage 4 standalone packet arrays. Descriptor layout is fixed at 24 bytes:
+ * pointer at 0, uint32 length at 8, capacity at 12, family at 16, reserved at 20.
+ * count is 0..32 and stride must be 24. Family is host AF_INET or AF_INET6.
+ * reserved must be zero in both directions.
+ * Enqueue requires 0 < length <= capacity <= 65535 and matching IP version.
+ * Dequeue requires length=family=reserved=0 and 0 < capacity <= 65535.
+ * All descriptors and referenced buffers belong to the caller and must remain
+ * valid and unmodified for the call. No pointer is retained. Output buffers
+ * must not overlap each other or the descriptors. Entire-batch validation
+ * precedes side effects. Invalid batches return ERR_ARGUMENT unchanged.
+ * Return is a processed PREFIX count, or a negative WINN_TUNNEL_ERR_* if no
+ * packet was processed. Zero count is a no-op on a live standalone handle.
+ * Enqueue preserves the bounded drop-oldest queue, counting evictions, and
+ * accepts the whole batch under the device lock. Dequeue waits for one packet
+ * (timeoutMS <= 0 waits until close/data), then drains available packets only.
+ * A short buffer leaves that packet queued: return ERR_TOO_LARGE if first,
+ * otherwise return the completed prefix. Suffix buffers/descriptors are intact.
+ * Close wakes blocked calls; handles are never reused. Scalar APIs remain.
+ */
+extern int WinsWinn3EnqueuePackets(long long handle, void *descriptors,
+                                  int count, int stride);
+extern int WinsWinn3DequeuePackets(long long handle, void *descriptors,
+                                  int count, int stride, int timeoutMS);
+
 #ifdef __cplusplus
 }
 #endif
```

### apple/EngineWrappers/WinnTunnelTestDouble.c

<!-- winn345-patch:diff -->
```diff
--- a/apple/EngineWrappers/WinnTunnelTestDouble.c
+++ b/apple/EngineWrappers/WinnTunnelTestDouble.c
@@ -49,12 +49,14 @@
 #include <stdlib.h>
 #include <string.h>
 #include <sys/time.h>
+#include <sys/socket.h>
 #include <time.h>
 
 #include "WinnTunnel.h"
 
 #define WINN_DOUBLE_MAX_TUNNELS 4
-#define WINN_DOUBLE_QUEUE_DEPTH 64
+#define WINN_DOUBLE_QUEUE_DEPTH 256
+#define WINN_DOUBLE_RELAY_QUEUE_DEPTH 64
 #define WINN_DOUBLE_MAX_PACKET_BYTES 2048
 
 /*
@@ -70,6 +72,8 @@
 
 typedef struct {
   int in_use;
+  int standalone;
+  long long handle;
   int closed;
   int udp_fd;
   uint64_t packets_in;
@@ -87,12 +91,14 @@
 static pthread_cond_t winn_double_ready = PTHREAD_COND_INITIALIZER;
 static WinnDoubleTunnel winn_double_tunnels[WINN_DOUBLE_MAX_TUNNELS];
 
+static long long winn_double_next_handle;
+
 static WinnDoubleTunnel *winn_double_lookup(long long handle) {
-  if (handle <= 0 || handle > WINN_DOUBLE_MAX_TUNNELS) {
-    return NULL;
-  }
-  WinnDoubleTunnel *tunnel = &winn_double_tunnels[handle - 1];
-  return tunnel->in_use ? tunnel : NULL;
+  for (int index = 0; index < WINN_DOUBLE_MAX_TUNNELS; index++) {
+    WinnDoubleTunnel *tunnel = &winn_double_tunnels[index];
+    if (tunnel->in_use && tunnel->handle == handle) return tunnel;
+  }
+  return NULL;
 }
 
 /* Every string this file hands back is allocated the same way it is freed. */
@@ -139,13 +145,14 @@
   pthread_mutex_lock(&winn_double_lock);
   long long handle = 0;
   for (int index = 0; index < WINN_DOUBLE_MAX_TUNNELS; index += 1) {
-    if (winn_double_tunnels[index].in_use) {
+    if (winn_double_tunnels[index].in_use && !winn_double_tunnels[index].closed) {
       continue;
     }
     memset(&winn_double_tunnels[index], 0, sizeof(WinnDoubleTunnel));
     winn_double_tunnels[index].in_use = 1;
     winn_double_tunnels[index].udp_fd = udpFD;
-    handle = (long long)(index + 1);
+    handle = ++winn_double_next_handle;
+    winn_double_tunnels[index].handle = handle;
     break;
   }
   pthread_mutex_unlock(&winn_double_lock);
@@ -176,17 +183,23 @@
     pthread_mutex_unlock(&winn_double_lock);
     return WINN_TUNNEL_ERR_TOO_LARGE;
   }
-  if (tunnel->count == WINN_DOUBLE_QUEUE_DEPTH) {
-    /* Queue pressure is a drop, not an error: the real carrier can drop too. */
+  int depth = tunnel->standalone ? WINN_DOUBLE_QUEUE_DEPTH : WINN_DOUBLE_RELAY_QUEUE_DEPTH;
+  if (tunnel->count == depth) {
     tunnel->dropped += 1;
-    pthread_mutex_unlock(&winn_double_lock);
-    return length;
+    if (tunnel->standalone) {
+      tunnel->head = (tunnel->head + 1) % depth;
+      tunnel->count -= 1;
+    } else {
+      /* Preserve the relay double's drop-newest behavior. */
+      pthread_mutex_unlock(&winn_double_lock);
+      return length;
+    }
   }
 
   WinnDoublePacket *slot = &tunnel->queue[tunnel->tail];
   memcpy(slot->bytes, buffer, (size_t)length);
   slot->length = length;
-  tunnel->tail = (tunnel->tail + 1) % WINN_DOUBLE_QUEUE_DEPTH;
+  tunnel->tail = (tunnel->tail + 1) % depth;
   tunnel->count += 1;
   tunnel->packets_in += 1;
   tunnel->bytes_in += (uint64_t)length;
@@ -229,10 +242,15 @@
       return WINN_TUNNEL_ERR_ARGUMENT;
     }
 
+    int depth = tunnel->standalone ? WINN_DOUBLE_QUEUE_DEPTH : WINN_DOUBLE_RELAY_QUEUE_DEPTH;
     if (tunnel->count > 0) {
       WinnDoublePacket *slot = &tunnel->queue[tunnel->head];
       int length = slot->length;
-      tunnel->head = (tunnel->head + 1) % WINN_DOUBLE_QUEUE_DEPTH;
+      if (tunnel->standalone && length > capacity) {
+        pthread_mutex_unlock(&winn_double_lock);
+        return WINN_TUNNEL_ERR_TOO_LARGE;
+      }
+      tunnel->head = (tunnel->head + 1) % depth;
       tunnel->count -= 1;
       if (length > capacity) {
         /* Contract: drop rather than truncate, and say so. */
@@ -305,15 +323,146 @@
   WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
   if (tunnel != NULL) {
     /*
-     * in_use stays set so the handle keeps reporting WINN_TUNNEL_ERR_CLOSED
-     * rather than WINN_TUNNEL_ERR_HANDLE. A double does not need to recycle
-     * slots. The broadcast is what makes close unblock an in-flight read, which
-     * the contract requires.
+     * Keep a closed identity recognizable until its slot is reused. Each
+     * create assigns a fresh handle, so an old reader can never address the
+     * replacement tunnel. Broadcast wakes every in-flight read on close.
      */
     tunnel->closed = 1;
+    tunnel->count = 0;
   }
   pthread_cond_broadcast(&winn_double_ready);
   pthread_mutex_unlock(&winn_double_lock);
   /* Contract: NULL on success, including for an unknown handle. */
   return NULL;
 }
+
+/* Standalone loopback exercises the array ABI, not IP policy or encryption. */
+long long WinnTunnelCreateWithCarrier(char *configJSON, char *carrierProfileJSON,
+                                     int udpFD, char **errorOut) {
+  (void)configJSON;
+  (void)carrierProfileJSON;
+  (void)udpFD;
+  if (errorOut != NULL) {
+    *errorOut = winn_double_string("test double does not implement authenticated carriers");
+  }
+  return 0;
+}
+
+long long WinnTunnelCreateWinn3(char *configJSON, int udpFD, char **errorOut) {
+  long long handle = WinnTunnelCreate(configJSON, udpFD, errorOut);
+  pthread_mutex_lock(&winn_double_lock);
+  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
+  if (tunnel != NULL) tunnel->standalone = 1;
+  pthread_mutex_unlock(&winn_double_lock);
+  return handle;
+}
+
+static uint32_t winn_double_family(const void *data, uint32_t length) {
+  const uint8_t *bytes = data;
+  if (length >= 20 && bytes[0] >> 4 == 4) return AF_INET;
+  if (length >= 40 && bytes[0] >> 4 == 6) return AF_INET6;
+  return 0;
+}
+
+static int winn_double_validate(void *raw, int count, int stride, int enqueue) {
+  if (count < 0 || count > WINS_WINN3_BATCH_MAX || stride != WINS_WINN3_PACKET_STRIDE)
+    return WINN_TUNNEL_ERR_ARGUMENT;
+  if (count == 0) return 0;
+  uintptr_t start = (uintptr_t)raw;
+  uintptr_t end = start + (uintptr_t)(count * stride);
+  if (!raw || start % _Alignof(WinsWinn3PacketDescriptor) || end < start)
+    return WINN_TUNNEL_ERR_ARGUMENT;
+  WinsWinn3PacketDescriptor *packets = raw;
+  for (int i = 0; i < count; i++) {
+    WinsWinn3PacketDescriptor *p = &packets[i];
+    uintptr_t lo = (uintptr_t)p->data, hi = lo + p->capacity;
+    if (!p->data || p->reserved || !p->capacity || p->capacity > WINS_WINN3_PACKET_MAX ||
+        hi < lo || (lo < end && start < hi)) return WINN_TUNNEL_ERR_ARGUMENT;
+    if (enqueue) {
+      if (!p->length || p->length > p->capacity || !p->family ||
+          winn_double_family(p->data, p->length) != p->family)
+        return WINN_TUNNEL_ERR_ARGUMENT;
+      /* The double's storage is intentionally smaller than the production ceiling. */
+      if (p->length > WINN_DOUBLE_MAX_PACKET_BYTES) return WINN_TUNNEL_ERR_TOO_LARGE;
+    } else {
+      if (p->length || p->family) return WINN_TUNNEL_ERR_ARGUMENT;
+      for (int j = 0; j < i; j++) {
+        uintptr_t other = (uintptr_t)packets[j].data;
+        if (lo < other + packets[j].capacity && other < hi)
+          return WINN_TUNNEL_ERR_ARGUMENT;
+      }
+    }
+  }
+  return 0;
+}
+
+int WinsWinn3EnqueuePackets(long long handle, void *raw, int count, int stride) {
+  int code = winn_double_validate(raw, count, stride, 1);
+  if (code) return code;
+  pthread_mutex_lock(&winn_double_lock);
+  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
+  if (!tunnel || !tunnel->standalone) code = WINN_TUNNEL_ERR_HANDLE;
+  else if (tunnel->closed) code = WINN_TUNNEL_ERR_CLOSED;
+  else {
+    WinsWinn3PacketDescriptor *packets = raw;
+    for (int i = 0; i < count; i++) {
+      if (tunnel->count == WINN_DOUBLE_QUEUE_DEPTH) {
+        tunnel->head = (tunnel->head + 1) % WINN_DOUBLE_QUEUE_DEPTH;
+        tunnel->count--;
+        tunnel->dropped++;
+      }
+      WinnDoublePacket *slot = &tunnel->queue[tunnel->tail];
+      memcpy(slot->bytes, packets[i].data, packets[i].length);
+      slot->length = (int)packets[i].length;
+      tunnel->tail = (tunnel->tail + 1) % WINN_DOUBLE_QUEUE_DEPTH;
+      tunnel->count++;
+      tunnel->packets_in++;
+      tunnel->bytes_in += packets[i].length;
+    }
+    pthread_cond_broadcast(&winn_double_ready);
+    code = count;
+  }
+  pthread_mutex_unlock(&winn_double_lock);
+  return code;
+}
+
+int WinsWinn3DequeuePackets(long long handle, void *raw, int count, int stride, int timeoutMS) {
+  int code = winn_double_validate(raw, count, stride, 0);
+  if (code) return code;
+  struct timespec deadline;
+  if (timeoutMS > 0) winn_double_deadline(&deadline, timeoutMS);
+  pthread_mutex_lock(&winn_double_lock);
+  for (;;) {
+    WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
+    if (!tunnel || !tunnel->standalone) { code = WINN_TUNNEL_ERR_HANDLE; break; }
+    if (tunnel->closed) { code = WINN_TUNNEL_ERR_CLOSED; break; }
+    if (!count) { code = 0; break; }
+    if (tunnel->count) {
+      WinsWinn3PacketDescriptor *packets = raw;
+      int n = 0;
+      while (n < count && tunnel->count) {
+        WinnDoublePacket *slot = &tunnel->queue[tunnel->head];
+        uint32_t family = winn_double_family(slot->bytes, (uint32_t)slot->length);
+        if (!family) { code = n ? n : WINN_TUNNEL_ERR_ARGUMENT; break; }
+        if ((uint32_t)slot->length > packets[n].capacity) {
+          code = n ? n : WINN_TUNNEL_ERR_TOO_LARGE;
+          break;
+        }
+        memcpy(packets[n].data, slot->bytes, (size_t)slot->length);
+        packets[n].length = (uint32_t)slot->length;
+        packets[n].family = family;
+        tunnel->packets_out++;
+        tunnel->bytes_out += (uint64_t)slot->length;
+        tunnel->head = (tunnel->head + 1) % WINN_DOUBLE_QUEUE_DEPTH;
+        tunnel->count--;
+        code = ++n;
+      }
+      break;
+    }
+    int waited = timeoutMS > 0 ? pthread_cond_timedwait(&winn_double_ready, &winn_double_lock, &deadline)
+                               : pthread_cond_wait(&winn_double_ready, &winn_double_lock);
+    if (waited == ETIMEDOUT) { code = WINN_TUNNEL_ERR_TIMEOUT; break; }
+  }
+  pthread_mutex_unlock(&winn_double_lock);
+  return code;
+}
```

### apple/WinsTunnelCore/WinsWinn3Datapath.swift

<!-- winn345-patch:diff -->
```diff
--- a/apple/WinsTunnelCore/WinsWinn3Datapath.swift
+++ b/apple/WinsTunnelCore/WinsWinn3Datapath.swift
@@ -103,6 +103,8 @@
   ) -> Int64
   typealias WriteInboundFn = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32) -> Int32
   typealias ReadOutboundFn = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32, Int32) -> Int32
+  typealias EnqueuePacketsFn = @convention(c) (Int64, UnsafeMutableRawPointer?, Int32, Int32) -> Int32
+  typealias DequeuePacketsFn = @convention(c) (Int64, UnsafeMutableRawPointer?, Int32, Int32, Int32) -> Int32
   typealias StatusJSONFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
   typealias CloseFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
   typealias FreeStringFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
@@ -113,6 +115,8 @@
   /// in at most one registry and these four are unambiguous for both datapaths.
   static let writeInboundSymbol = "WinnTunnelWriteInbound"
   static let readOutboundSymbol = "WinnTunnelReadOutbound"
+  static let enqueuePacketsSymbol = "WinsWinn3EnqueuePackets"
+  static let dequeuePacketsSymbol = "WinsWinn3DequeuePackets"
   static let statusJSONSymbol = "WinnTunnelStatusJSON"
   static let closeSymbol = "WinnTunnelClose"
   static let freeStringSymbol = "WinnTunnelFreeString"
@@ -136,6 +140,14 @@
     defer { dlclose(image) }
     guard let pointer = dlsym(image, name) else { return nil }
     return unsafeBitCast(pointer, to: type)
+  }
+
+  // Batch support is additive. A legacy archive (or a partial symbol pair)
+  // uses the scalar path in both directions for the session.
+  static var batchSymbolsAvailable: Bool {
+    WinsWinn3PacketDescriptor.layoutAvailable
+      && resolve(enqueuePacketsSymbol, as: EnqueuePacketsFn.self) != nil
+      && resolve(dequeuePacketsSymbol, as: DequeuePacketsFn.self) != nil
   }
 
   /// Whether every symbol the pump needs is present.
@@ -179,6 +191,28 @@
   }
 }
 
+// Fixed C layout, checked before use because this file is compiled without a
+// bridging header. C header static assertions and the host harness check it too.
+struct WinsWinn3PacketDescriptor {
+  var data: UnsafeMutableRawPointer?
+  var length: UInt32 = 0
+  var capacity: UInt32
+  var family: UInt32 = 0
+  var reserved: UInt32 = 0
+
+  static let stride = 24
+  static let maximumCount = 32
+  static let maximumPacket = 65535
+  static var layoutAvailable: Bool {
+    MemoryLayout<Self>.stride == stride && MemoryLayout<Self>.alignment == 8
+      && MemoryLayout<Self>.offset(of: \.data) == 0
+      && MemoryLayout<Self>.offset(of: \.length) == 8
+      && MemoryLayout<Self>.offset(of: \.capacity) == 12
+      && MemoryLayout<Self>.offset(of: \.family) == 16
+      && MemoryLayout<Self>.offset(of: \.reserved) == 20
+  }
+}
+
 // MARK: - the pump
 
 /// Owns one winn/3 standalone handle and moves packets across the C ABI.
@@ -239,6 +273,9 @@
   private var hostToEnginePackets: UInt64 = 0
   private var engineToHostPackets: UInt64 = 0
 
+  private var batchEnqueue: WinsWinn3ABI.EnqueuePacketsFn?
+  private var batchDequeue: WinsWinn3ABI.DequeuePacketsFn?
+
   private var readBufferCapacity = WinsWinn3Datapath.readBufferFloor
 
   /// The handle, or 0 when the session has not started or has been closed.
@@ -304,7 +341,12 @@
     // a drop that looks exactly like a censored link.
     let published = statusFields()[WinsWinn3PromotionGate.innerMTUKey]
     let innerMTU = Int(clamping: WinsWinn3PromotionGate.unsignedValue(published))
-    readBufferCapacity = max(innerMTU + 128, Self.readBufferFloor)
+    readBufferCapacity = max(min(innerMTU, WinsWinn3PacketDescriptor.maximumPacket - 128) + 128,
+                             Self.readBufferFloor)
+    if WinsWinn3ABI.batchSymbolsAvailable {
+      batchEnqueue = WinsWinn3ABI.resolve(WinsWinn3ABI.enqueuePacketsSymbol, as: WinsWinn3ABI.EnqueuePacketsFn.self)
+      batchDequeue = WinsWinn3ABI.resolve(WinsWinn3ABI.dequeuePacketsSymbol, as: WinsWinn3ABI.DequeuePacketsFn.self)
+    }
   }
 
   // MARK: pump
@@ -340,23 +382,78 @@
   /// host -> engine. Re-arms itself from inside its own completion handler,
   /// which is the only supported way to read an `NEPacketTunnelFlow`.
   private func pumpHostToEngine(relay: WinsWinn3PacketRelay) {
-    relay.readPackets { [weak self] packets, _ in
-      guard let self else { return }
-      guard self.shouldKeepPumping() else { return }
-
-      for packet in packets {
-        // The tun layer is the validator, and it is the ONLY validator: it
-        // checks source address, martian destination, size and checksum, and
-        // counts what it drops. Filtering here would be a second rule in a
-        // second language that can drift from the first, and a packet dropped
-        // silently on this side is a packet the engine's own counters cannot
-        // explain.
-        guard self.writeToEngine(packet) else { break }
-      }
-
-      guard self.shouldKeepPumping() else { return }
-      self.pumpHostToEngine(relay: relay)
-    }
+    relay.readPackets { [weak self] packets, protocols in
+      guard let self, self.shouldKeepPumping() else { return }
+      // Validate all callback metadata before even the first chunk crosses C.
+      guard packets.count == protocols.count,
+            zip(packets, protocols).allSatisfy({ packet, family in
+              Self.packetFamily(packet).map { NSNumber(value: $0) == family } ?? false
+            }) else {
+        self.counterLock.lock()
+        self.hostToEngineRefused &+= UInt64(packets.count)
+        self.counterLock.unlock()
+        if self.shouldKeepPumping() { self.pumpHostToEngine(relay: relay) }
+        return
+      }
+
+      if let enqueue = self.batchEnqueue {
+        for offset in stride(from: 0, to: packets.count, by: WinsWinn3PacketDescriptor.maximumCount) {
+          let end = min(offset + WinsWinn3PacketDescriptor.maximumCount, packets.count)
+          guard self.enqueueChunk(Array(packets[offset..<end]), protocols: Array(protocols[offset..<end]),
+                                  enqueue: enqueue) else { break }
+        }
+      } else {
+        for packet in packets {
+          guard self.writeToEngine(packet) else { break }
+        }
+      }
+      if self.shouldKeepPumping() { self.pumpHostToEngine(relay: relay) }
+    }
+  }
+
+  private static func packetFamily(_ packet: Data) -> Int32? {
+    guard packet.count <= WinsWinn3PacketDescriptor.maximumPacket,
+          let first = packet.first else { return nil }
+    if first >> 4 == 4 && packet.count >= 20 { return AF_INET }
+    if first >> 4 == 6 && packet.count >= 40 { return AF_INET6 }
+    return nil
+  }
+
+  private func enqueueChunk(_ packets: [Data], protocols: [NSNumber],
+                            enqueue: WinsWinn3ABI.EnqueuePacketsFn) -> Bool {
+    guard shouldKeepPumping() else { return false }
+    let live = currentHandle
+    let descriptors = UnsafeMutablePointer<WinsWinn3PacketDescriptor>.allocate(capacity: packets.count)
+    descriptors.initialize(repeating: WinsWinn3PacketDescriptor(data: nil, capacity: 0), count: packets.count)
+    defer {
+      descriptors.deinitialize(count: packets.count)
+      descriptors.deallocate()
+    }
+    // Nest the closures, bounded at 32, so every Data pointer remains valid
+    // until the ONE foreign call returns. withExtendedLifetime alone would
+    // not pin small inline Data or a temporary withUnsafeBytes representation.
+    func pin(_ index: Int) -> Int32 {
+      if index == packets.count {
+        return enqueue(live, UnsafeMutableRawPointer(descriptors), Int32(packets.count),
+                       Int32(WinsWinn3PacketDescriptor.stride))
+      }
+      return packets[index].withUnsafeBytes { raw in
+        descriptors[index] = WinsWinn3PacketDescriptor(
+          data: UnsafeMutableRawPointer(mutating: raw.baseAddress), length: UInt32(raw.count),
+          capacity: UInt32(raw.count), family: protocols[index].uint32Value)
+        let result = pin(index + 1)
+        descriptors[index].data = nil
+        return result
+      }
+    }
+    let count = pin(0)
+    guard count <= packets.count else { return false }
+    counterLock.lock()
+    hostToEnginePackets &+= UInt64(max(0, count))
+    hostToEngineRefused &+= UInt64(packets.count - max(0, Int(count)))
+    counterLock.unlock()
+    if count >= 0 { return true }
+    return !(WinsWinn3ABIStatus(rawValue: count)?.isTerminal ?? true)
   }
 
   /// Hands one packet to the engine. Returns false when the loop should stop.
@@ -395,6 +492,10 @@
 
   /// engine -> host. Runs on its own thread because the read blocks.
   private func pumpEngineToHost(relay: WinsWinn3PacketRelay) {
+    if let dequeue = batchDequeue {
+      pumpEngineBatchToHost(relay: relay, dequeue: dequeue)
+      return
+    }
     guard let read = WinsWinn3ABI.resolve(WinsWinn3ABI.readOutboundSymbol, as: WinsWinn3ABI.ReadOutboundFn.self)
     else { return }
 
@@ -440,23 +541,61 @@
     }
   }
 
+  private func pumpEngineBatchToHost(relay: WinsWinn3PacketRelay,
+                                     dequeue: WinsWinn3ABI.DequeuePacketsFn) {
+    let batchSize = WinsWinn3PacketDescriptor.maximumCount
+    let capacity = readBufferCapacity
+    let storage = UnsafeMutableRawPointer.allocate(byteCount: capacity * batchSize, alignment: 8)
+    defer { storage.deallocate() }
+    while shouldKeepPumping() {
+      var descriptors = (0..<batchSize).map {
+        WinsWinn3PacketDescriptor(data: storage.advanced(by: $0 * capacity), capacity: UInt32(capacity))
+      }
+      let count = descriptors.withUnsafeMutableBytes {
+        dequeue(currentHandle, $0.baseAddress, Int32(batchSize), Int32(WinsWinn3PacketDescriptor.stride),
+                Self.readTimeoutMilliseconds)
+      }
+      guard shouldKeepPumping() else { return }
+      if count > 0 {
+        guard count <= batchSize else { return }
+        var packets: [Data] = []
+        var protocols: [NSNumber] = []
+        for index in 0..<Int(count) {
+          let descriptor = descriptors[index]
+          guard descriptor.length > 0, descriptor.length <= capacity,
+                descriptor.capacity == capacity, descriptor.reserved == 0,
+                descriptor.data == storage.advanced(by: index * capacity) else { return }
+          let packet = Data(bytes: storage.advanced(by: index * capacity), count: Int(descriptor.length))
+          guard let family = Self.packetFamily(packet), UInt32(family) == descriptor.family else { return }
+          packets.append(packet)
+          protocols.append(NSNumber(value: family))
+        }
+        recordDelivery(packets, protocols: protocols, relay: relay)
+      } else if count < 0 {
+        // TOO_LARGE retains the head in Go. Retrying with this same buffer
+        // would spin indefinitely, so stop this reader and record the refusal.
+        if count == WinsWinn3ABIStatus.tooLarge.rawValue {
+          counterLock.lock()
+          engineToHostRefused &+= 1
+          counterLock.unlock()
+        }
+        if WinsWinn3ABIStatus(rawValue: count)?.isTerminal ?? true { return }
+      }
+    }
+  }
+
   private func deliverToHost(_ packet: Data, relay: WinsWinn3PacketRelay) {
-    // winn/3's inner layer is IPv4 here; `winn3_inner_ipv6` reports whether the
-    // session negotiated a v6 assignment at all, and a config whose floor
-    // cannot carry one is refused at create. Reading the version off the packet
-    // rather than off the config keeps the two from disagreeing.
-    let family: Int32
-    if let first = packet.first, (first >> 4) == 6 {
-      family = AF_INET6
-    } else {
-      family = AF_INET
-    }
-    let accepted = relay.writePackets([packet], withProtocols: [NSNumber(value: family)])
+    guard shouldKeepPumping(), let family = Self.packetFamily(packet) else { return }
+    recordDelivery([packet], protocols: [NSNumber(value: family)], relay: relay)
+  }
+
+  private func recordDelivery(_ packets: [Data], protocols: [NSNumber], relay: WinsWinn3PacketRelay) {
+    let accepted = relay.writePackets(packets, withProtocols: protocols)
     counterLock.lock()
     if accepted {
-      engineToHostPackets &+= 1
+      engineToHostPackets &+= UInt64(packets.count)
     } else {
-      engineToHostRefused &+= 1
+      engineToHostRefused &+= UInt64(packets.count)
     }
     counterLock.unlock()
   }
```

### ios/Runner.xcodeproj/project.pbxproj

<!-- winn345-patch:diff -->
```diff
--- a/ios/Runner.xcodeproj/project.pbxproj
+++ b/ios/Runner.xcodeproj/project.pbxproj
@@ -1259,6 +1259,8 @@
 					"-Wl,-u,_WinnTunnelMaxDatagram",
 					"-Wl,-u,_WinnTunnelCreate",
 					"-Wl,-u,_WinnTunnelCreateWinn3",
+					"-Wl,-u,_WinsWinn3EnqueuePackets",
+					"-Wl,-u,_WinsWinn3DequeuePackets",
 					"-Wl,-u,_WinnTunnelCreateWithCarrier",
 					"-Wl,-u,_WinnTunnelWriteInbound",
 					"-Wl,-u,_WinnTunnelReadOutbound",
@@ -1332,6 +1334,8 @@
 					"-Wl,-u,_WinnTunnelMaxDatagram",
 					"-Wl,-u,_WinnTunnelCreate",
 					"-Wl,-u,_WinnTunnelCreateWinn3",
+					"-Wl,-u,_WinsWinn3EnqueuePackets",
+					"-Wl,-u,_WinsWinn3DequeuePackets",
 					"-Wl,-u,_WinnTunnelCreateWithCarrier",
 					"-Wl,-u,_WinnTunnelWriteInbound",
 					"-Wl,-u,_WinnTunnelReadOutbound",
@@ -1398,6 +1402,8 @@
 					"-Wl,-u,_WinnTunnelMaxDatagram",
 					"-Wl,-u,_WinnTunnelCreate",
 					"-Wl,-u,_WinnTunnelCreateWinn3",
+					"-Wl,-u,_WinsWinn3EnqueuePackets",
+					"-Wl,-u,_WinsWinn3DequeuePackets",
 					"-Wl,-u,_WinnTunnelCreateWithCarrier",
 					"-Wl,-u,_WinnTunnelWriteInbound",
 					"-Wl,-u,_WinnTunnelReadOutbound",
```

### macos/Runner.xcodeproj/project.pbxproj

<!-- winn345-patch:diff -->
```diff
--- a/macos/Runner.xcodeproj/project.pbxproj
+++ b/macos/Runner.xcodeproj/project.pbxproj
@@ -1052,6 +1052,8 @@
 					"-Wl,-u,_WinnTunnelMaxDatagram",
 					"-Wl,-u,_WinnTunnelCreate",
 					"-Wl,-u,_WinnTunnelCreateWinn3",
+					"-Wl,-u,_WinsWinn3EnqueuePackets",
+					"-Wl,-u,_WinsWinn3DequeuePackets",
 					"-Wl,-u,_WinnTunnelCreateWithCarrier",
 					"-Wl,-u,_WinnTunnelWriteInbound",
 					"-Wl,-u,_WinnTunnelReadOutbound",
@@ -1124,6 +1126,8 @@
 					"-Wl,-u,_WinnTunnelMaxDatagram",
 					"-Wl,-u,_WinnTunnelCreate",
 					"-Wl,-u,_WinnTunnelCreateWinn3",
+					"-Wl,-u,_WinsWinn3EnqueuePackets",
+					"-Wl,-u,_WinsWinn3DequeuePackets",
 					"-Wl,-u,_WinnTunnelCreateWithCarrier",
 					"-Wl,-u,_WinnTunnelWriteInbound",
 					"-Wl,-u,_WinnTunnelReadOutbound",
@@ -1184,6 +1188,8 @@
 					"-Wl,-u,_WinnTunnelMaxDatagram",
 					"-Wl,-u,_WinnTunnelCreate",
 					"-Wl,-u,_WinnTunnelCreateWinn3",
+					"-Wl,-u,_WinsWinn3EnqueuePackets",
+					"-Wl,-u,_WinsWinn3DequeuePackets",
 					"-Wl,-u,_WinnTunnelCreateWithCarrier",
 					"-Wl,-u,_WinnTunnelWriteInbound",
 					"-Wl,-u,_WinnTunnelReadOutbound",
```

### tools/build_winn_protocol_engine.sh

<!-- winn345-patch:diff -->
```diff
--- a/tools/build_winn_protocol_engine.sh
+++ b/tools/build_winn_protocol_engine.sh
@@ -2078,7 +2078,7 @@
   ARTIFACT_LABEL="datapath engine (c-archive)"
   ARTIFACT_ROLE="datapath"
   ARCHIVE_MODE=1
-  ARCHIVE_SYMBOLS="_WinnTunnelContractVersion _WinnTunnelProtocolVersion _WinnTunnelMaxDatagram _WinnTunnelCreate _WinnTunnelCreateWinn3 _WinnTunnelWriteInbound _WinnTunnelReadOutbound _WinnTunnelStatusJSON _WinnTunnelClose _WinnTunnelFreeString"
+  ARCHIVE_SYMBOLS="_WinnTunnelContractVersion _WinnTunnelProtocolVersion _WinnTunnelMaxDatagram _WinnTunnelCreate _WinnTunnelCreateWinn3 _WinsWinn3EnqueuePackets _WinsWinn3DequeuePackets _WinnTunnelWriteInbound _WinnTunnelReadOutbound _WinnTunnelStatusJSON _WinnTunnelClose _WinnTunnelFreeString"
 }
 
 # select_server_engine switches this invocation to the control-plane
```

### windows/winn3_engine/direct_control.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/windows/winn3_engine/direct_control.go
@@ -0,0 +1,48 @@
+package main
+
+import (
+	"encoding/json"
+	"errors"
+	"io"
+	"path/filepath"
+	"strings"
+)
+
+func parseDirectStart(line string) (string, error) {
+	if len(line) == 0 || len(line) > 64<<10 {
+		return "", errors.New("direct start size invalid")
+	}
+	dec := json.NewDecoder(strings.NewReader(line))
+	token, err := dec.Token()
+	if err != nil || token != json.Delim('{') {
+		return "", errors.New("direct start must be an object")
+	}
+	if !dec.More() {
+		return "", errors.New("direct profile required")
+	}
+	key, err := dec.Token()
+	if err != nil || key != "profile" {
+		return "", errors.New("direct start accepts only profile")
+	}
+	var path string
+	if err := dec.Decode(&path); err != nil {
+		return "", err
+	}
+	if dec.More() {
+		return "", errors.New("direct start has extra or duplicate fields")
+	}
+	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
+		return "", errors.New("direct start object incomplete")
+	}
+	if dec.Decode(new(any)) != io.EOF {
+		return "", errors.New("direct start trailing input")
+	}
+	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
+		return "", errors.New("direct profile requires an absolute local path")
+	}
+	// Windows device and network namespaces are not local profile files.
+	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
+		return "", errors.New("direct profile cannot use a device or network namespace")
+	}
+	return path, nil
+}
```

### windows/winn3_engine/direct_device.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/windows/winn3_engine/direct_device.go
@@ -0,0 +1,113 @@
+package main
+
+import (
+	"errors"
+	"io"
+	"sync"
+
+	"winsvpn.local/winnprotocol/winn3/tun"
+)
+
+// directDevice hands packets straight to the Winn tun layer. No socket, queue,
+// or borrowed Wintun slice crosses this boundary. Close refuses new calls,
+// wakes the existing receive, and drains all ring access before freeing it.
+type directDevice struct {
+	side     tunSide
+	mtu      int
+	stats    *counters
+	wake     func()
+	free     func() error
+	mu       sync.Mutex
+	closed   bool
+	active   sync.WaitGroup
+	once     sync.Once
+	wakeOnce sync.Once
+	closeErr error
+}
+
+func (d *directDevice) enter() bool {
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	if d.closed {
+		return false
+	}
+	d.active.Add(1)
+	return true
+}
+
+func (d *directDevice) MTU() int { return d.mtu }
+
+func (d *directDevice) ReadPacket(buf []byte) (int, error) {
+	if !d.enter() {
+		return 0, io.ErrClosedPipe
+	}
+	defer d.active.Done()
+	for {
+		packet, release, err := d.side.receivePacket()
+		if errors.Is(err, errTunAgain) {
+			if err = d.side.waitReadable(); err != nil {
+				return 0, err
+			}
+			continue
+		}
+		if err != nil {
+			return 0, err
+		}
+		if problem := classifyInnerPacket(packet, d.mtu); problem != nil {
+			countRefusal(d.stats, problem)
+			release()
+			continue
+		}
+		if len(buf) < len(packet) {
+			release()
+			return 0, io.ErrShortBuffer
+		}
+		n := copy(buf, packet)
+		release()
+		d.stats.tunToSeam.Add(1)
+		return n, nil
+	}
+}
+
+func (d *directDevice) WritePacket(packet []byte) (int, error) {
+	if !d.enter() {
+		return 0, io.ErrClosedPipe
+	}
+	defer d.active.Done()
+	if problem := classifyInnerPacket(packet, d.mtu); problem != nil {
+		countRefusal(d.stats, problem)
+		return 0, problem
+	}
+	if err := d.side.sendPacket(packet); err != nil {
+		if errors.Is(err, errTunRingFull) {
+			d.stats.dropRingFull.Add(1)
+		} else {
+			// Fatal writes also wake an idle read, which tells the runtime to
+			// stop. Ring pressure is the sole recoverable write refusal.
+			d.stop()
+		}
+		// Failed delivery must remain an error: the tun layer must never count
+		// a full ring as RxPackets and thereby permit posture promotion.
+		return 0, err
+	}
+	d.stats.seamToTun.Add(1)
+	return len(packet), nil
+}
+
+func (d *directDevice) Close() error {
+	d.once.Do(func() {
+		d.stop()
+		d.active.Wait()
+		d.closeErr = d.free()
+	})
+	return d.closeErr
+}
+
+func (d *directDevice) stop() {
+	d.mu.Lock()
+	d.closed = true
+	d.mu.Unlock()
+	d.wakeOnce.Do(d.wake)
+}
+
+var _ tun.Device = (*directDevice)(nil)
```

### windows/winn3_engine/direct_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/windows/winn3_engine/direct_test.go
@@ -0,0 +1,186 @@
+package main
+
+import (
+	"bytes"
+	"errors"
+	"io"
+	"path/filepath"
+	"strconv"
+	"sync"
+	"sync/atomic"
+	"testing"
+	"time"
+)
+
+func directFixture(t *testing.T) (*directDevice, *fakeTun, *atomic.Int32) {
+	t.Helper()
+	f := newFakeTun()
+	freed := new(atomic.Int32)
+	d := &directDevice{side: f, mtu: harnessMTU, stats: &counters{},
+		wake: func() { close(f.closed) }, free: func() error { freed.Add(1); return nil }}
+	t.Cleanup(func() { _ = d.Close() })
+	return d, f, freed
+}
+
+func TestDirectReadOwnsBytesAndReleasesRejectedPackets(t *testing.T) {
+	d, f, _ := directFixture(t)
+	f.push([]byte{0x45})
+	f.push(ipv4(harnessMTU+1, harnessMTU+1))
+	p := ipv4(48, 48)
+	want := bytes.Clone(p)
+	f.push(p)
+	buf := make([]byte, harnessMTU)
+	n, err := d.ReadPacket(buf)
+	if err != nil || !bytes.Equal(buf[:n], want) {
+		t.Fatalf("read = %d, %v", n, err)
+	}
+	clear(p)
+	if !bytes.Equal(buf[:n], want) {
+		t.Fatal("read aliases released native buffer")
+	}
+	if f.released.Load() != 3 || d.stats.dropInvalid.Load() != 1 || d.stats.dropOversize.Load() != 1 {
+		t.Fatal("missing release or refusal accounting")
+	}
+	f.push(ipv4(48, 48))
+	if n, err := d.ReadPacket(make([]byte, 20)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
+		t.Fatalf("short read = %d, %v", n, err)
+	}
+	if f.released.Load() != 4 {
+		t.Fatal("short read leaked borrowed packet")
+	}
+}
+
+func TestDirectFullRingIsNeverSuccessfulDelivery(t *testing.T) {
+	d, f, _ := directFixture(t)
+	f.ringFull.Store(true)
+	if n, err := d.WritePacket(ipv4(48, 48)); n != 0 || !errors.Is(err, errTunRingFull) {
+		t.Fatalf("write = %d, %v", n, err)
+	}
+	if d.stats.seamToTun.Load() != 0 || d.stats.dropRingFull.Load() != 1 {
+		t.Fatal("failed delivery counted as success")
+	}
+	f.ringFull.Store(false)
+	if n, err := d.WritePacket(ipv4(48, 48)); n != 48 || err != nil {
+		t.Fatalf("write = %d, %v", n, err)
+	}
+	if len(<-f.in) != 48 {
+		t.Fatal("wrong native packet")
+	}
+	for _, p := range [][]byte{{0x45}, ipv4(harnessMTU+1, harnessMTU+1)} {
+		if n, err := d.WritePacket(p); n != 0 || err == nil {
+			t.Fatal("malformed packet reached native ring")
+		}
+	}
+}
+
+func TestDirectCloseWakesIdleReaderAndRefusesNewCalls(t *testing.T) {
+	d, _, freed := directFixture(t)
+	done := make(chan error, 1)
+	go func() { _, err := d.ReadPacket(make([]byte, harnessMTU)); done <- err }()
+	var closers sync.WaitGroup
+	for range 16 {
+		closers.Go(func() { _ = d.Close() })
+	}
+	closers.Wait()
+	select {
+	case err := <-done:
+		if err == nil {
+			t.Fatal("closed read succeeded")
+		}
+	case <-time.After(time.Second):
+		t.Fatal("reader stuck")
+	}
+	if freed.Load() != 1 {
+		t.Fatalf("native frees = %d", freed.Load())
+	}
+	if _, err := d.ReadPacket(make([]byte, harnessMTU)); !errors.Is(err, io.ErrClosedPipe) {
+		t.Fatal("post-close read admitted")
+	}
+	if _, err := d.WritePacket(ipv4(48, 48)); !errors.Is(err, io.ErrClosedPipe) {
+		t.Fatal("post-close write admitted")
+	}
+}
+
+type heldSendTun struct {
+	*fakeTun
+	entered chan struct{}
+	release chan struct{}
+}
+
+func (f *heldSendTun) sendPacket([]byte) error { close(f.entered); <-f.release; return nil }
+
+func TestDirectCloseDoesNotFreeUnderActiveWrite(t *testing.T) {
+	d, f, freed := directFixture(t)
+	held := &heldSendTun{fakeTun: f, entered: make(chan struct{}), release: make(chan struct{})}
+	d.side = held
+	written := make(chan struct{})
+	go func() { _, _ = d.WritePacket(ipv4(48, 48)); close(written) }()
+	<-held.entered
+	closed := make(chan struct{})
+	go func() { _ = d.Close(); close(closed) }()
+	<-f.closed
+	if freed.Load() != 0 {
+		t.Fatal("ring freed under active send")
+	}
+	select {
+	case <-closed:
+		t.Fatal("Close returned before native call")
+	default:
+	}
+	close(held.release)
+	<-written
+	select {
+	case <-closed:
+	case <-time.After(time.Second):
+		t.Fatal("Close did not drain")
+	}
+	if freed.Load() != 1 {
+		t.Fatal("ring was not freed exactly once")
+	}
+}
+
+func TestDirectControlRejectsAmbiguity(t *testing.T) {
+	path := filepath.Join(t.TempDir(), "profile.json")
+	valid := `{"profile":` + strconv.Quote(path) + `}`
+	if got, err := parseDirectStart(valid); err != nil || got != path {
+		t.Fatalf("valid = %q, %v", got, err)
+	}
+	for _, raw := range []string{
+		`{}`, `null`, `[]`, `{"profile":"relative.json"}`, `{"Profile":` + strconv.Quote(path) + `}`,
+		valid + ` {}`, valid + ` garbage`, `{"profile":null}`, `{"profile":` + strconv.Quote(path) + `,"profile":` + strconv.Quote(path) + `}`,
+		`{"profile":` + strconv.Quote(path) + `,"engine_port":123}`, `{"profile":"//server/profile.json"}`,
+	} {
+		if _, err := parseDirectStart(raw); err == nil {
+			t.Fatalf("accepted %s", raw)
+		}
+	}
+}
+
+type fatalSendTun struct{ *fakeTun }
+
+func (f fatalSendTun) sendPacket([]byte) error { return errTunClosed }
+
+func TestDirectFatalWriteWakesReaderAndClosesAdmission(t *testing.T) {
+	d, f, freed := directFixture(t)
+	d.side = fatalSendTun{f}
+	done := make(chan error, 1)
+	go func() { _, err := d.ReadPacket(make([]byte, harnessMTU)); done <- err }()
+	if _, err := d.WritePacket(ipv4(48, 48)); !errors.Is(err, errTunClosed) {
+		t.Fatalf("fatal write = %v", err)
+	}
+	select {
+	case err := <-done:
+		if err == nil {
+			t.Fatal("fatal write did not stop read")
+		}
+	case <-time.After(time.Second):
+		t.Fatal("idle reader stranded")
+	}
+	if _, err := d.WritePacket(ipv4(48, 48)); !errors.Is(err, io.ErrClosedPipe) {
+		t.Fatal("fatal write left adapter admission open")
+	}
+	_ = d.Close()
+	if freed.Load() != 1 {
+		t.Fatal("fatal write cleanup did not free once")
+	}
+}
```

### windows/winn3_engine/direct_windows.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/windows/winn3_engine/direct_windows.go
@@ -0,0 +1,108 @@
+package main
+
+import (
+	"bufio"
+	"context"
+	"fmt"
+	"os"
+	"os/signal"
+	"sync/atomic"
+	"time"
+
+	"golang.org/x/sys/windows"
+	"golang.zx2c4.com/wintun"
+	"winsvpn.local/winnprotocol/winn3/hostqueue"
+)
+
+// runDirectCandidate is a separate, explicit control protocol for an
+// authenticated LocalSystem host. The existing supervisor does not select it.
+// Stdin: one JSON line {"profile":"absolute protected profile path"}, then
+// EOF to stop. Stdout: ready line then desktop status JSON. No host-port or
+// engine-port exists in this mode, and no child datapath is launched.
+func runDirectCandidate(stopEvent windows.Handle) error {
+	ctx, cancel := context.WithCancel(context.Background())
+	defer cancel()
+	signals := make(chan os.Signal, 1)
+	signal.Notify(signals, os.Interrupt, windows.SIGTERM)
+	defer signal.Stop(signals)
+	go func() {
+		if result, _ := windows.WaitForSingleObject(stopEvent, windows.INFINITE); result == windows.WAIT_OBJECT_0 {
+			cancel()
+		}
+	}()
+	go func() {
+		select {
+		case <-signals:
+			cancel()
+		case <-ctx.Done():
+		}
+	}()
+	// A stuck native call or status pipe must not retain a privileged adapter.
+	// Exiting leaves ring reclamation to the OS; it never frees under a caller.
+	go func() {
+		<-ctx.Done()
+		time.Sleep(pumpQuiesceTimeout)
+		os.Exit(9)
+	}()
+	control := bufio.NewScanner(os.Stdin)
+	control.Buffer(make([]byte, 4096), 64<<10)
+	if !control.Scan() {
+		return fmt.Errorf("direct start command missing")
+	}
+	profile, err := parseDirectStart(control.Text())
+	if err != nil {
+		return err
+	}
+	go func() {
+		// Any second command or EOF ends this one-session process. There is no
+		// live profile replacement or implicit downgrade to the relay mode.
+		control.Scan()
+		cancel()
+	}()
+	var stats counters
+	var luid uint64
+	var mtu int
+	runtime, err := hostqueue.Open(ctx, profile, func(floor int) (hostqueue.Device, error) {
+		adapter, err := wintun.CreateAdapter(adapterName, tunnelType, nil)
+		if err != nil {
+			return nil, err
+		}
+		session, err := adapter.StartSession(ringCapacity)
+		if err != nil {
+			_ = adapter.Close()
+			return nil, err
+		}
+		quit, err := windows.CreateEvent(nil, 1, 0, nil)
+		if err != nil || quit == 0 {
+			session.End()
+			_ = adapter.Close()
+			return nil, fmt.Errorf("create direct quit event: %w", err)
+		}
+		var stopping atomic.Bool
+		side := wintunSide{session: session, readWait: session.ReadWaitEvent(), quit: quit, stopping: &stopping}
+		luid, mtu = adapter.LUID(), floor
+		return &directDevice{side: side, mtu: floor, stats: &stats,
+			wake: func() { stopping.Store(true); _ = windows.SetEvent(quit) },
+			free: func() error {
+				session.End()
+				_ = windows.CloseHandle(quit)
+				return adapter.Close()
+			},
+		}, nil
+	})
+	if err != nil {
+		return err
+	}
+	defer runtime.Close()
+	if _, err := fmt.Fprintf(os.Stdout, "ready name=%s luid=%d mtu=%d floor-mtu=%d ipv6=%v\n",
+		adapterName, luid, mtu, winn3ShippingFloorInnerMTU, mtu >= winn3IPv6MinLinkMTU); err != nil {
+		return err
+	}
+	err = runtime.Run(ctx, os.Stdout)
+	fmt.Fprintf(os.Stderr, "winn3-direct: tun-to-engine=%d engine-to-tun=%d invalid=%d oversize=%d ring-full=%d\n",
+		stats.tunToSeam.Load(), stats.seamToTun.Load(), stats.dropInvalid.Load(), stats.dropOversize.Load(), stats.dropRingFull.Load())
+	if ctx.Err() != nil {
+		return nil
+	}
+	return err
+}
```

### windows/winn3_engine/go.mod

<!-- winn345-patch:diff -->
```diff
--- a/windows/winn3_engine/go.mod
+++ b/windows/winn3_engine/go.mod
@@ -1,4 +1,7 @@
-// The Windows Winn Protocol v3 tun relay.
+// The Windows Winn Protocol v3 tun relay and opt-in direct engine candidate.
+// The historical relay-only dependency rationale below applies to the default
+// mode. The direct candidate imports the local Winn module for its own crypto;
+// Wintun itself remains outside the Winn protocol module's dependencies.
 //
 // Deliberately its own module, for the same reason as its siblings
 // windows/awg_engine and windows/winn_framing_fixture: nesting keeps this
@@ -27,9 +30,18 @@
 // installer would be two different loss profiles for the same driver.
 module winsvpn.local/winsvpnwinn3engine
 
-go 1.25.0
+go 1.27.0
 
 require (
-	golang.org/x/sys v0.46.0
+	golang.org/x/sys v0.47.0
 	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
+	winsvpn.local/winnprotocol v0.0.0
 )
+
+require (
+	github.com/cloudflare/circl v1.6.3 // indirect
+	golang.org/x/crypto v0.54.0 // indirect
+)
+
+// Required only to instantiate the opt-in direct Winn v3 candidate in-process.
+replace winsvpn.local/winnprotocol => ../../winn_protocol_experimental
```

### windows/winn3_engine/go.sum

<!-- winn345-patch:diff -->
```diff
--- a/windows/winn3_engine/go.sum
+++ b/windows/winn3_engine/go.sum
@@ -1,4 +1,8 @@
-golang.org/x/sys v0.46.0 h1:noSf2Fq6F8DBgS+LysIkx7rIExoNHJsxOAtPp4rthXw=
-golang.org/x/sys v0.46.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
+github.com/cloudflare/circl v1.6.3 h1:9GPOhQGF9MCYUeXyMYlqTR6a5gTrgR/fBLXvUgtVcg8=
+github.com/cloudflare/circl v1.6.3/go.mod h1:2eXP6Qfat4O/Yhh8BznvKnJ+uzEoTQ6jVKJRn81BiS4=
+golang.org/x/crypto v0.54.0 h1:YLIA59K4fiNzHzjnZt2tUJQjQtUWfWbeHBqKtk3eScw=
+golang.org/x/crypto v0.54.0/go.mod h1:KWL8ny2AZdGR2cWmzeHrp2azQPGogOv+HeQaVEXC2dk=
+golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
+golang.org/x/sys v0.47.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
 golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 h1:B82qJJgjvYKsXS9jeunTOisW56dUokqW/FOteYJJ/yg=
 golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2/go.mod h1:deeaetjYA+DHMHg+sMSMI58GrEteJUUzzw7en6TJQcI=
```

### windows/winn3_engine/main_windows.go

<!-- winn345-patch:diff -->
```diff
--- a/windows/winn3_engine/main_windows.go
+++ b/windows/winn3_engine/main_windows.go
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: MIT
+//
+// The default relay is described below. --in-process-candidate instead runs
+// the Winn client and direct Wintun device together, before any relay socket
+// is created. Its distinct control protocol is documented in direct_windows.go.
+// The existing supervisor does not select this study candidate.
 //
 // The Windows tun relay for Winn Protocol v3.
 //
@@ -223,8 +228,10 @@
 		os.Exit(0)
 	}
 
-	// No arguments, ever. See the header.
-	if len(os.Args) != 1 || !runningAsLocalSystem() {
+	// The direct candidate is explicit and retains the same privilege and
+	// singleton boundary. No argument can select a profile, endpoint or key.
+	directCandidate := len(os.Args) == 2 && os.Args[1] == "--in-process-candidate"
+	if (len(os.Args) != 1 && !directCandidate) || !runningAsLocalSystem() {
 		os.Exit(2)
 	}
 	stopEvent, ok := createStopEvent()
@@ -232,6 +239,13 @@
 		os.Exit(3)
 	}
 	defer windows.CloseHandle(stopEvent)
+	if directCandidate {
+		if err := runDirectCandidate(stopEvent); err != nil {
+			fmt.Fprintln(os.Stderr, "winn3-direct: candidate stopped")
+			os.Exit(10)
+		}
+		return
+	}
 
 	out := bufio.NewWriter(os.Stdout)
 	fail := func(code int, format string, args ...any) {
```

### winn_protocol_experimental/cdatapath/batch_test_support.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/batch_test_support.go
@@ -0,0 +1,61 @@
+//go:build darwin && winn3_batch_test
+
+package main
+
+/*
+#include <stdlib.h>
+#include "winn_packet_batch.h"
+extern int WinsWinn3EnqueuePackets(long long, void *, int, int);
+extern int WinsWinn3DequeuePackets(long long, void *, int, int, int);
+extern char *WinnTunnelClose(long long);
+static int batch_enqueue(long long h, void *p, int n, int s) {
+  return WinsWinn3EnqueuePackets(h, p, n, s);
+}
+static int batch_dequeue(long long h, void *p, int n, int s, int ms) {
+  return WinsWinn3DequeuePackets(h, p, n, s, ms);
+}
+*/
+import "C"
+
+import "unsafe"
+
+// Test-only helpers use C allocations and a real Go -> C -> exported Go call.
+// No Go pointer is stored in descriptors or survives a foreign call.
+type nativeBatch struct {
+	raw         unsafe.Pointer
+	packets     []C.WinsWinn3PacketDescriptor
+	allocations []unsafe.Pointer
+}
+
+func newNativeBatch(count, capacity int) *nativeBatch {
+	b := &nativeBatch{raw: C.calloc(C.size_t(count), C.size_t(C.WINS_WINN3_PACKET_STRIDE))}
+	b.packets = unsafe.Slice((*C.WinsWinn3PacketDescriptor)(b.raw), count)
+	for i := range b.packets {
+		p := C.calloc(1, C.size_t(capacity))
+		b.allocations = append(b.allocations, p)
+		b.packets[i].data = p
+		b.packets[i].capacity = C.uint32_t(capacity)
+	}
+	return b
+}
+func (b *nativeBatch) free() {
+	for _, p := range b.allocations {
+		C.free(p)
+	}
+	C.free(b.raw)
+}
+func (b *nativeBatch) bytes(i int) []byte {
+	return unsafe.Slice((*byte)(b.allocations[i]), int(b.packets[i].capacity))
+}
+func (b *nativeBatch) setPacket(i int, packet []byte) {
+	copy(b.bytes(i), packet)
+	b.packets[i].length = C.uint32_t(len(packet))
+	b.packets[i].family = C.uint32_t(batchPacketFamily(packet))
+}
+func (b *nativeBatch) enqueue(handle int64, count, stride int) int {
+	return int(C.batch_enqueue(C.longlong(handle), b.raw, C.int(count), C.int(stride)))
+}
+func (b *nativeBatch) dequeue(handle int64, count, stride, timeout int) int {
+	return int(C.batch_dequeue(C.longlong(handle), b.raw, C.int(count), C.int(stride), C.int(timeout)))
+}
+func nativeClose(handle int64) { WinnTunnelFreeString(C.WinnTunnelClose(C.longlong(handle))) }
```

### winn_protocol_experimental/cdatapath/tests/apple_batch_harness.swift

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/tests/apple_batch_harness.swift
@@ -0,0 +1,173 @@
+import Darwin
+import Foundation
+
+@_silgen_name("WinnTunnelWriteInbound")
+func nativeWrite(_ h: Int64, _ p: UnsafeMutablePointer<CChar>?, _ n: Int32) -> Int32
+@_silgen_name("WinnTunnelReadOutbound")
+func nativeRead(_ h: Int64, _ p: UnsafeMutablePointer<CChar>?, _ n: Int32, _ ms: Int32) -> Int32
+#if BATCH_TEST
+@_silgen_name("WinsWinn3EnqueuePackets")
+func nativeEnqueue(_ h: Int64, _ p: UnsafeMutableRawPointer?, _ n: Int32, _ s: Int32) -> Int32
+@_silgen_name("WinsWinn3DequeuePackets")
+func nativeDequeue(_ h: Int64, _ p: UnsafeMutableRawPointer?, _ n: Int32, _ s: Int32, _ ms: Int32) -> Int32
+#endif
+
+let metricsLock = NSLock()
+var enqueueCounts: [Int] = []
+var dequeueCounts: [Int] = []
+var scalarWrites = 0
+var shortenEnqueue = false
+
+func countedWrite(_ h: Int64, _ p: UnsafeMutablePointer<CChar>?, _ n: Int32) -> Int32 {
+  metricsLock.lock(); scalarWrites += 1; metricsLock.unlock()
+  return nativeWrite(h, p, n)
+}
+func countedRead(_ h: Int64, _ p: UnsafeMutablePointer<CChar>?, _ n: Int32, _ ms: Int32) -> Int32 {
+  let result = nativeRead(h, p, n, ms)
+  if result > 0 { metricsLock.lock(); dequeueCounts.append(1); metricsLock.unlock() }
+  return result
+}
+#if BATCH_TEST
+func countedEnqueue(_ h: Int64, _ p: UnsafeMutableRawPointer?, _ n: Int32, _ s: Int32) -> Int32 {
+  metricsLock.lock()
+  enqueueCounts.append(Int(n))
+  let short = shortenEnqueue
+  metricsLock.unlock()
+  return nativeEnqueue(h, p, short ? min(n, 3) : n, s)
+}
+func countedDequeue(_ h: Int64, _ p: UnsafeMutableRawPointer?, _ n: Int32, _ s: Int32, _ ms: Int32) -> Int32 {
+  let result = nativeDequeue(h, p, n, s, ms)
+  if result > 0 { metricsLock.lock(); dequeueCounts.append(Int(result)); metricsLock.unlock() }
+  return result
+}
+#endif
+
+final class BatchRelay: WinsWinn3PacketRelay {
+  let lock = NSLock()
+  var pending: ([Data], [NSNumber])?
+  var callback: (@Sendable ([Data], [NSNumber]) -> Void)?
+  var writes: [[Data]] = []
+  var families: [[NSNumber]] = []
+  var accept = true
+
+  init(_ packets: [Data], _ protocols: [NSNumber]) { pending = (packets, protocols) }
+  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
+    lock.lock()
+    let batch = pending
+    pending = nil
+    callback = completionHandler
+    lock.unlock()
+    if let batch { completionHandler(batch.0, batch.1) }
+  }
+  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
+    lock.lock(); defer { lock.unlock() }
+    writes.append(packets); families.append(protocols)
+    return accept
+  }
+  var packetCount: Int { lock.lock(); defer { lock.unlock() }; return writes.reduce(0) { $0 + $1.count } }
+}
+
+func check(_ value: @autoclosure () -> Bool, _ message: String) {
+  if !value() { fputs("FAIL: \(message)\n", stderr); exit(1) }
+}
+func waitUntil(_ predicate: () -> Bool) {
+  let deadline = Date().addingTimeInterval(3)
+  while !predicate() && Date() < deadline { usleep(1000) }
+  check(predicate(), "bounded wait")
+}
+func packet(_ i: Int) -> Data {
+  let version: UInt8 = i % 2 == 0 ? 4 : 6
+  let size = version == 4 ? 20 : 40
+  // A sliced Data tests storage with a nonzero base index, alongside normal Data.
+  var bytes = Data(repeating: 0, count: size + 7)
+  bytes[7] = version << 4
+  bytes[bytes.count - 1] = UInt8(i)
+  return i % 3 == 0 ? bytes[7...] : Data(bytes[7...])
+}
+func resetMetrics() {
+  metricsLock.lock(); enqueueCounts = []; dequeueCounts = []; scalarWrites = 0; shortenEnqueue = false; metricsLock.unlock()
+}
+func start(_ relay: BatchRelay) throws -> WinsWinn3Datapath {
+  let pump = WinsWinn3Datapath()
+  try pump.start(document: "{}", carrierDescriptor: -1)
+  pump.resume(relay: relay)
+  return pump
+}
+
+@main struct AppleBatchHarness {
+  static func main() throws {
+    WinsWinn3ABI.testSymbols = [
+      WinsWinn3ABI.writeInboundSymbol: unsafeBitCast(countedWrite as WinsWinn3ABI.WriteInboundFn, to: UnsafeMutableRawPointer.self),
+      WinsWinn3ABI.readOutboundSymbol: unsafeBitCast(countedRead as WinsWinn3ABI.ReadOutboundFn, to: UnsafeMutableRawPointer.self)
+    ]
+    #if BATCH_TEST
+    WinsWinn3ABI.testSymbols?[WinsWinn3ABI.enqueuePacketsSymbol] = unsafeBitCast(countedEnqueue as WinsWinn3ABI.EnqueuePacketsFn, to: UnsafeMutableRawPointer.self)
+    WinsWinn3ABI.testSymbols?[WinsWinn3ABI.dequeuePacketsSymbol] = unsafeBitCast(countedDequeue as WinsWinn3ABI.DequeuePacketsFn, to: UnsafeMutableRawPointer.self)
+    check(WinsWinn3ABI.batchSymbolsAvailable, "batch symbol pair resolves")
+    #else
+    check(!WinsWinn3ABI.batchSymbolsAvailable, "missing/partial batch pair selects scalar compatibility")
+    #endif
+    check(WinsWinn3PacketDescriptor.layoutAvailable, "descriptor stride and every offset")
+    let packets = (0..<70).map(packet)
+    let protocols = (0..<70).map { NSNumber(value: $0 % 2 == 0 ? AF_INET : AF_INET6) }
+    let relay = BatchRelay(packets, protocols)
+    let pump = try start(relay)
+    waitUntil { relay.packetCount == packets.count }
+    check(pump.stop() == nil, "close succeeds")
+    relay.lock.lock()
+    let written = relay.writes, families = relay.families
+    relay.lock.unlock()
+    check(written.flatMap { $0 } == packets, "mixed IPv4/IPv6 Data bytes and FIFO order")
+    check(families.flatMap { $0 } == protocols, "matching protocol arrays")
+    check(written.map { $0.count } == dequeueCounts, "one writePackets arrays call per positive dequeue")
+    #if BATCH_TEST
+    check(enqueueCounts == [32, 32, 6] && scalarWrites == 0, "one foreign call per callback chunk")
+    check(written.allSatisfy { $0.count <= 32 }, "bounded dequeue")
+    #else
+    check(scalarWrites == 70, "legacy scalar symbols remain functional")
+    #endif
+    let fields = pump.pumpStatusFields()
+    check(fields["winn3_datapath_proof_host_to_engine_packets"] as? Int == 70, "enqueue packet accounting")
+    check(fields["winn3_datapath_proof_engine_to_host_packets"] as? Int == 70, "dequeue packet accounting")
+
+    // Invalid metadata at the tail must prevent even the first valid chunk.
+    for badKind in 0..<3 {
+      resetMetrics()
+      var badProtocols = protocols
+      var badPackets = packets
+      if badKind == 0 { badProtocols.removeLast() }
+      if badKind == 1 { badProtocols[69] = NSNumber(value: AF_INET) }
+      if badKind == 2 { badPackets[69] = Data([0x60]) }
+      let invalidRelay = BatchRelay(badPackets, badProtocols)
+      let invalidPump = try start(invalidRelay)
+      check(invalidPump.pumpStatusFields()["winn3_datapath_proof_host_to_engine_refused"] as? Int == 70,
+            "invalid callback refused as a whole")
+      check(enqueueCounts.isEmpty && scalarWrites == 0, "invalid tail causes zero foreign writes")
+      check(invalidPump.stop() == nil, "idle blocking reader closes")
+    }
+
+    #if BATCH_TEST
+    resetMetrics()
+    shortenEnqueue = true
+    let partialRelay = BatchRelay(Array(packets.prefix(10)), Array(protocols.prefix(10)))
+    let partialPump = try start(partialRelay)
+    waitUntil { partialRelay.packetCount == 3 }
+    partialPump.stop()
+    check(enqueueCounts == [10], "partial prefix is not retried or duplicated")
+    let partial = partialPump.pumpStatusFields()
+    check(partial["winn3_datapath_proof_host_to_engine_packets"] as? Int == 3 &&
+          partial["winn3_datapath_proof_host_to_engine_refused"] as? Int == 7, "partial prefix accounting")
+    #endif
+
+    resetMetrics()
+    let refusedRelay = BatchRelay(Array(packets.prefix(4)), Array(protocols.prefix(4)))
+    refusedRelay.accept = false
+    let refusedPump = try start(refusedRelay)
+    waitUntil { refusedRelay.packetCount == 4 }
+    refusedPump.stop()
+    check(refusedPump.pumpStatusFields()["winn3_datapath_proof_engine_to_host_refused"] as? Int == 4,
+          "writePackets refusal counts packets, not batches")
+    check(refusedPump.stop() == nil && !refusedPump.isRunning, "idempotent close")
+    print("PASS: Apple array/scalar host pump contract, data ownership, family, prefix, close")
+  }
+}
```

### winn_protocol_experimental/cdatapath/tests/batch_header_contract.c

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/tests/batch_header_contract.c
@@ -0,0 +1,17 @@
+#include <stddef.h>
+#if defined(WINN_BATCH_APPLE_HEADER)
+#include "../../../apple/EngineWrappers/WinnTunnel.h"
+#else
+#include "../winn_datapath.h"
+#endif
+
+_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "stride");
+_Static_assert(_Alignof(WinsWinn3PacketDescriptor) == 8, "alignment");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, data) == 0, "data offset");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "length offset");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, capacity) == 12, "capacity offset");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, family) == 16, "family offset");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, reserved) == 20, "reserved offset");
+
+int (*enqueue_signature)(long long, void *, int, int) = WinsWinn3EnqueuePackets;
+int (*dequeue_signature)(long long, void *, int, int, int) = WinsWinn3DequeuePackets;
```

### winn_protocol_experimental/cdatapath/tests/run_apple_batch_harness.sh

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/tests/run_apple_batch_harness.sh
@@ -0,0 +1,26 @@
+#!/bin/bash
+set -euo pipefail
+root=$(cd "$(dirname "$0")/../../.." && pwd)
+work=$(mktemp -d /tmp/winn3-apple-batch.XXXXXX)
+trap 'rm -rf "$work"' EXIT
+cd "$root"
+xcrun clang -fobjc-arc -Wall -Wextra -Werror -c tools/verify_apple_winn_seam_awg_stub.m -o "$work/awg.o"
+xcrun clang -fobjc-arc -Wall -Wextra -Werror -I apple/EngineWrappers -c apple/EngineWrappers/WinsWinnPacketEngine.m -o "$work/wrapper.o"
+for mode in batch scalar partial; do
+  cflags=(-DWINS_WINN_ENGINE_TESTING=1)
+  swiftflags=(-swift-version 5)
+  if [[ "$mode" == batch ]]; then
+    swiftflags+=(-D BATCH_TEST)
+  elif [[ "$mode" == scalar ]]; then
+    cflags+=(-DWinsWinn3EnqueuePackets=LegacyEnqueue -DWinsWinn3DequeuePackets=LegacyDequeue)
+  else
+    cflags+=(-DWinsWinn3DequeuePackets=LegacyDequeue)
+  fi
+  xcrun clang -Wall -Wextra -Werror "${cflags[@]}" -c apple/EngineWrappers/WinnTunnelTestDouble.c -o "$work/double.o"
+  xcrun swiftc "${swiftflags[@]}" apple/WinsTunnelCore/*.swift \
+    winn_protocol_experimental/cdatapath/tests/apple_batch_harness.swift \
+    "$work/awg.o" "$work/wrapper.o" "$work/double.o" \
+    -framework Foundation -framework NetworkExtension -framework Security \
+    -Xlinker -export_dynamic -o "$work/harness"
+  "$work/harness"
+done
```

### winn_protocol_experimental/cdatapath/winn_datapath.h

<!-- winn345-patch:diff -->
```diff
--- a/winn_protocol_experimental/cdatapath/winn_datapath.h
+++ b/winn_protocol_experimental/cdatapath/winn_datapath.h
@@ -402,6 +402,33 @@
 extern long long WinnTunnelCreateWinn3(char *configJSON, int udpFD,
                                        char **errorOut);
 
+#include "winn_packet_batch.h"
+
+/*
+ * Stage 4 standalone packet arrays. Descriptor layout is fixed at 24 bytes:
+ * pointer at 0, uint32 length at 8, capacity at 12, family at 16, reserved at 20.
+ * count is 0..32 and stride must be 24. Family is host AF_INET or AF_INET6.
+ * reserved must be zero in both directions.
+ * Enqueue requires 0 < length <= capacity <= 65535 and matching IP version.
+ * Dequeue requires length=family=reserved=0 and 0 < capacity <= 65535.
+ * All descriptors and referenced buffers belong to the caller and must remain
+ * valid and unmodified for the call. No pointer is retained. Output buffers
+ * must not overlap each other or the descriptors. Entire-batch validation
+ * precedes side effects. Invalid batches return ERR_ARGUMENT unchanged.
+ * Return is a processed PREFIX count, or a negative WINN_TUNNEL_ERR_* if no
+ * packet was processed. Zero count is a no-op on a live standalone handle.
+ * Enqueue preserves the bounded drop-oldest queue, counting evictions, and
+ * accepts the whole batch under the device lock. Dequeue waits for one packet
+ * (timeoutMS <= 0 waits until close/data), then drains available packets only.
+ * A short buffer leaves that packet queued: return ERR_TOO_LARGE if first,
+ * otherwise return the completed prefix. Suffix buffers/descriptors are intact.
+ * Close wakes blocked calls; handles are never reused. Scalar APIs remain.
+ */
+extern int WinsWinn3EnqueuePackets(long long handle, void *descriptors,
+                                  int count, int stride);
+extern int WinsWinn3DequeuePackets(long long handle, void *descriptors,
+                                  int count, int stride, int timeoutMS);
+
 #ifdef __cplusplus
 }
 #endif
```

### winn_protocol_experimental/cdatapath/winn_datapath_batch.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/winn_datapath_batch.go
@@ -0,0 +1,220 @@
+//go:build darwin
+
+package main
+
+/*
+#ifndef WINS_WINN3_PACKET_BATCH_H
+#define WINS_WINN3_PACKET_BATCH_H
+#include <stddef.h>
+#include <stdint.h>
+
+// Apple 64-bit ABI. All integers are in host byte order.
+#define WINS_WINN3_BATCH_MAX 32
+#define WINS_WINN3_PACKET_STRIDE 24
+#define WINS_WINN3_PACKET_MAX 65535
+
+typedef struct WinsWinn3PacketDescriptor {
+  void *data;
+  uint32_t length;
+  uint32_t capacity;
+  uint32_t family;
+  uint32_t reserved;
+} WinsWinn3PacketDescriptor;
+
+#if defined(__cplusplus)
+static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
+static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
+#else
+_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
+#endif
+#endif
+
+#include <sys/socket.h>
+*/
+import "C"
+
+import (
+	"time"
+	"unsafe"
+)
+
+const winn3BatchMax = 32
+
+// A descriptor references caller memory only during the foreign call. The
+// queues contain independent Go byte copies, never descriptors or C pointers.
+func batchDescriptors(raw unsafe.Pointer, count, stride int, enqueue bool) ([]C.WinsWinn3PacketDescriptor, int) {
+	if count < 0 || count > winn3BatchMax || stride != C.WINS_WINN3_PACKET_STRIDE {
+		return nil, errArgument
+	}
+	if count == 0 {
+		return nil, 0
+	}
+	if raw == nil || uintptr(raw)%unsafe.Alignof(C.WinsWinn3PacketDescriptor{}) != 0 {
+		return nil, errArgument
+	}
+	start := uintptr(raw)
+	end := start + uintptr(count*stride)
+	if end < start {
+		return nil, errArgument
+	}
+	desc := unsafe.Slice((*C.WinsWinn3PacketDescriptor)(raw), count)
+	// Check the entire batch before any queue, counter, or caller output changes.
+	for i := range desc {
+		p := &desc[i]
+		if p.data == nil || p.reserved != 0 || p.capacity == 0 || p.capacity > C.WINS_WINN3_PACKET_MAX {
+			return nil, errArgument
+		}
+		lo := uintptr(p.data)
+		hi := lo + uintptr(p.capacity)
+		if hi < lo || (lo < end && start < hi) {
+			return nil, errArgument
+		}
+		if enqueue {
+			if p.length == 0 || p.length > p.capacity {
+				return nil, errArgument
+			}
+			packet := unsafe.Slice((*byte)(p.data), int(p.length))
+			if batchPacketFamily(packet) != uint32(p.family) || p.family == 0 {
+				return nil, errArgument
+			}
+		} else {
+			if p.length != 0 || p.family != 0 {
+				return nil, errArgument
+			}
+			for j := 0; j < i; j++ {
+				other := uintptr(desc[j].data)
+				if lo < other+uintptr(desc[j].capacity) && other < hi {
+					return nil, errArgument
+				}
+			}
+		}
+	}
+	return desc, 0
+}
+
+// IP policy remains in tun. This boundary checks only the minimum header and
+// the family/version agreement needed to interpret NEPacketTunnelFlow arrays.
+func batchPacketFamily(packet []byte) uint32 {
+	if len(packet) >= 20 && packet[0]>>4 == 4 {
+		return uint32(C.AF_INET)
+	}
+	if len(packet) >= 40 && packet[0]>>4 == 6 {
+		return uint32(C.AF_INET6)
+	}
+	return 0
+}
+
+// WinsWinn3EnqueuePackets accepts a validated batch atomically relative to
+// close and other queue operations. The existing drop-oldest queue policy is
+// preserved: a full queue still accepts every new packet and counts eviction.
+//
+//export WinsWinn3EnqueuePackets
+func WinsWinn3EnqueuePackets(handle C.longlong, descriptors unsafe.Pointer, count C.int, stride C.int) C.int {
+	desc, code := batchDescriptors(descriptors, int(count), int(stride), true)
+	if code != 0 {
+		return C.int(code)
+	}
+	t := lookupWinn3(int64(handle))
+	if t == nil {
+		return errHandle
+	}
+	d := t.dev
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	if t.closed.Load() || d.closed {
+		return errClosed
+	}
+	for _, p := range desc {
+		packet := unsafe.Slice((*byte)(p.data), int(p.length))
+		cp := append([]byte(nil), packet...)
+		if len(d.outbound) >= d.depth {
+			d.outbound[0] = nil
+			d.outbound = d.outbound[1:]
+			d.droppedOutbound.Add(1)
+		}
+		d.outbound = append(d.outbound, cp)
+	}
+	if len(desc) > 0 {
+		d.notEmpty.Broadcast()
+	}
+	return count
+}
+
+// WinsWinn3DequeuePackets waits only for the first packet and then copies the
+// available prefix. A short destination leaves that packet queued. A positive
+// prefix wins over a later error; all suffix descriptors and bytes stay intact.
+//
+//export WinsWinn3DequeuePackets
+func WinsWinn3DequeuePackets(handle C.longlong, descriptors unsafe.Pointer, count C.int, stride C.int, timeoutMS C.int) C.int {
+	desc, code := batchDescriptors(descriptors, int(count), int(stride), false)
+	if code != 0 {
+		return C.int(code)
+	}
+	t := lookupWinn3(int64(handle))
+	if t == nil {
+		return errHandle
+	}
+	d := t.dev
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	if t.closed.Load() || d.closed {
+		return errClosed
+	}
+	if len(desc) == 0 {
+		return 0
+	}
+	deadline := time.Time{}
+	if timeoutMS > 0 {
+		deadline = time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
+	}
+	for len(d.inbound) == 0 && !d.closed && !t.closed.Load() {
+		if deadline.IsZero() {
+			d.notEmpty.Wait()
+			continue
+		}
+		remaining := time.Until(deadline)
+		if remaining <= 0 {
+			return errTimeout
+		}
+		// Locking in the callback prevents a timeout wakeup from being lost
+		// between scheduling the timer and entering Cond.Wait.
+		timer := time.AfterFunc(remaining, func() {
+			d.mu.Lock()
+			d.notEmpty.Broadcast()
+			d.mu.Unlock()
+		})
+		d.notEmpty.Wait()
+		timer.Stop()
+	}
+	if t.closed.Load() || d.closed {
+		return errClosed
+	}
+	n := 0
+	for n < len(desc) && len(d.inbound) > 0 {
+		packet := d.inbound[0]
+		family := batchPacketFamily(packet)
+		if family == 0 {
+			if n == 0 {
+				return errArgument
+			}
+			break
+		}
+		if len(packet) > int(desc[n].capacity) {
+			if n == 0 {
+				return errTooLarge
+			}
+			break
+		}
+		copy(unsafe.Slice((*byte)(desc[n].data), int(desc[n].capacity)), packet)
+		desc[n].length = C.uint32_t(len(packet))
+		desc[n].family = C.uint32_t(family)
+		d.inbound[0] = nil
+		d.inbound = d.inbound[1:]
+		n++
+	}
+	if n > 0 {
+		d.notFull.Broadcast()
+	}
+	return C.int(n)
+}
```

### winn_protocol_experimental/cdatapath/winn_datapath_batch_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/winn_datapath_batch_test.go
@@ -0,0 +1,307 @@
+//go:build darwin && winn3_batch_test
+
+package main
+
+import (
+	"bytes"
+	"runtime"
+	"sync"
+	"testing"
+	"time"
+	"unsafe"
+)
+
+func batchIP(version, tag byte) []byte {
+	n := 20
+	if version == 6 {
+		n = 40
+	}
+	p := make([]byte, n)
+	p[0] = version << 4
+	p[n-1] = tag
+	return p
+}
+
+func registerBatchDevice(t *testing.T) (int64, *abiDevice) {
+	t.Helper()
+	d := newABIDevice(1500)
+	h := nextHandle.Add(1)
+	winn3Mu.Lock()
+	winn3Registry[h] = &winn3Tunnel{dev: d}
+	winn3Mu.Unlock()
+	t.Cleanup(func() {
+		winn3Mu.Lock()
+		delete(winn3Registry, h)
+		winn3Mu.Unlock()
+		d.close()
+	})
+	return h, d
+}
+
+func TestBatchEnqueueValidatesEntireArrayAndCopies(t *testing.T) {
+	h, d := registerBatchDevice(t)
+	b := newNativeBatch(32, 64)
+	for i := range b.packets {
+		b.setPacket(i, batchIP(4, byte(i)))
+	}
+	b.packets[31].family = 30 // AF_INET6 on Darwin, contradicts version 4.
+	if n := b.enqueue(h, 32, 24); n != errArgument {
+		t.Fatalf("invalid tail = %d", n)
+	}
+	if len(d.outbound) != 0 || d.droppedOutbound.Load() != 0 {
+		t.Fatal("invalid batch had side effects")
+	}
+	b.setPacket(31, batchIP(6, 31))
+	if n := b.enqueue(h, 32, 24); n != 32 {
+		t.Fatalf("enqueue = %d", n)
+	}
+	for i := range b.packets {
+		clear(b.bytes(i))
+	}
+	b.free()
+	runtime.GC()
+	buf := make([]byte, 64)
+	for i := 0; i < 32; i++ {
+		n, err := d.ReadPacket(buf)
+		version := byte(4)
+		if i == 31 {
+			version = 6
+		}
+		if err != nil || !bytes.Equal(buf[:n], batchIP(version, byte(i))) {
+			t.Fatalf("copy/order %d: %x %v", i, buf[:n], err)
+		}
+	}
+}
+
+func TestBatchBadDescriptorsHaveNoSideEffects(t *testing.T) {
+	cases := []struct {
+		name   string
+		mutate func(*nativeBatch)
+	}{
+		{"nil-data", func(b *nativeBatch) { b.packets[1].data = nil }},
+		{"zero-length", func(b *nativeBatch) { b.packets[1].length = 0 }},
+		{"length-over-capacity", func(b *nativeBatch) { b.packets[1].length = 65 }},
+		{"zero-capacity", func(b *nativeBatch) { b.packets[1].capacity = 0 }},
+		{"huge-capacity", func(b *nativeBatch) { b.packets[1].capacity = 65536 }},
+		{"reserved", func(b *nativeBatch) { b.packets[1].reserved = 1 }},
+		{"bad-family", func(b *nativeBatch) { b.packets[1].family = 99 }},
+		{"bad-version", func(b *nativeBatch) { b.bytes(1)[0] = 0x70 }},
+		{"short-header", func(b *nativeBatch) { b.packets[1].length = 19 }},
+		{"descriptor-alias", func(b *nativeBatch) { b.packets[1].data = b.raw }},
+	}
+	for _, tc := range cases {
+		t.Run(tc.name, func(t *testing.T) {
+			h, d := registerBatchDevice(t)
+			b := newNativeBatch(2, 64)
+			defer b.free()
+			b.setPacket(0, batchIP(4, 1))
+			b.setPacket(1, batchIP(4, 2))
+			tc.mutate(b)
+			if n := b.enqueue(h, 2, 24); n != errArgument {
+				t.Fatalf("got %d", n)
+			}
+			if len(d.outbound) != 0 {
+				t.Fatal("prefix was enqueued before tail validation")
+			}
+		})
+	}
+}
+
+func TestBatchEnvelopeLimits(t *testing.T) {
+	h, _ := registerBatchDevice(t)
+	b := newNativeBatch(1, 64)
+	defer b.free()
+	b.setPacket(0, batchIP(4, 1))
+	for _, tc := range [][2]int{{-1, 24}, {33, 24}, {1, 0}, {1, 23}, {1, 32}} {
+		if n := b.enqueue(h, tc[0], tc[1]); n != errArgument {
+			t.Fatalf("%v = %d", tc, n)
+		}
+	}
+	if n := b.enqueue(h, 0, 24); n != 0 {
+		t.Fatalf("empty = %d", n)
+	}
+	if n := b.enqueue(-1, 1, 24); n != errHandle {
+		t.Fatalf("unknown = %d", n)
+	}
+	original := b.raw
+	b.raw = unsafe.Add(original, 1)
+	if n := b.enqueue(h, 1, 24); n != errArgument {
+		t.Fatalf("unaligned = %d", n)
+	}
+	b.raw = nil
+	if n := b.enqueue(h, 1, 24); n != errArgument {
+		t.Fatalf("nil = %d", n)
+	}
+	b.raw = original
+}
+
+func TestBatchPressurePreservesDropOldest(t *testing.T) {
+	h, d := registerBatchDevice(t)
+	d.depth = 3
+	b := newNativeBatch(4, 64)
+	defer b.free()
+	for i := range b.packets {
+		b.setPacket(i, batchIP(4, byte(i)))
+	}
+	if n := b.enqueue(h, 4, 24); n != 4 {
+		t.Fatalf("enqueue = %d", n)
+	}
+	if d.droppedOutbound.Load() != 1 || len(d.outbound) != 3 {
+		t.Fatal("queue policy changed")
+	}
+	for i, p := range d.outbound {
+		if p[19] != byte(i+1) {
+			t.Fatal("wrong eviction/order")
+		}
+	}
+}
+
+func TestBatchDequeuePrefixAndShortBufferRetry(t *testing.T) {
+	h, d := registerBatchDevice(t)
+	d.WritePacket(batchIP(4, 1))
+	d.WritePacket(batchIP(6, 2))
+	d.WritePacket(batchIP(4, 3))
+	b := newNativeBatch(3, 64)
+	defer b.free()
+	b.packets[1].capacity = 20
+	for i := range b.packets {
+		for j := range b.bytes(i) {
+			b.bytes(i)[j] = 0xa5
+		}
+	}
+	if n := b.dequeue(h, 3, 24, 1); n != 1 {
+		t.Fatalf("prefix = %d", n)
+	}
+	if b.packets[0].length != 20 || b.packets[0].family != 2 || b.packets[1].length != 0 || b.packets[2].family != 0 {
+		t.Fatal("metadata changed outside prefix")
+	}
+	if b.bytes(1)[0] != 0xa5 || b.bytes(2)[0] != 0xa5 || len(d.inbound) != 2 {
+		t.Fatal("suffix/queue mutated")
+	}
+	short := newNativeBatch(1, 20)
+	defer short.free()
+	if n := short.dequeue(h, 1, 24, 1); n != errTooLarge || len(d.inbound) != 2 {
+		t.Fatalf("short retry = %d", n)
+	}
+	out := newNativeBatch(3, 64)
+	defer out.free()
+	if n := out.dequeue(h, 3, 24, 1); n != 2 {
+		t.Fatalf("retry = %d", n)
+	}
+	if out.packets[0].family != 30 || out.packets[1].family != 2 {
+		t.Fatal("mixed family lost")
+	}
+	if !bytes.Equal(out.bytes(0)[:40], batchIP(6, 2)) || !bytes.Equal(out.bytes(1)[:20], batchIP(4, 3)) {
+		t.Fatal("wrong packet bytes")
+	}
+}
+
+func TestBatchDequeueRejectsTailBeforeConsumption(t *testing.T) {
+	for _, alias := range []bool{false, true} {
+		h, d := registerBatchDevice(t)
+		d.WritePacket(batchIP(4, 1))
+		b := newNativeBatch(2, 64)
+		if alias {
+			b.packets[1].data = b.packets[0].data
+		} else {
+			b.packets[1].family = 2
+		}
+		if n := b.dequeue(h, 2, 24, 1); n != errArgument {
+			t.Fatalf("invalid output = %d", n)
+		}
+		if len(d.inbound) != 1 || b.packets[0].length != 0 || b.bytes(0)[0] != 0 {
+			t.Fatal("invalid tail consumed/wrote prefix")
+		}
+		b.free()
+	}
+}
+
+func TestBatchDequeueTimeoutAndClose(t *testing.T) {
+	h, d := registerBatchDevice(t)
+	b := newNativeBatch(1, 64)
+	defer b.free()
+	start := time.Now()
+	if n := b.dequeue(h, 1, 24, 15); n != errTimeout {
+		t.Fatalf("timeout = %d", n)
+	}
+	if elapsed := time.Since(start); elapsed < 10*time.Millisecond || elapsed > time.Second {
+		t.Fatalf("deadline %v", elapsed)
+	}
+	done := make(chan int, 1)
+	go func() { done <- b.dequeue(h, 1, 24, 0) }()
+	time.Sleep(10 * time.Millisecond)
+	d.close()
+	select {
+	case n := <-done:
+		if n != errClosed {
+			t.Fatalf("close = %d", n)
+		}
+	case <-time.After(time.Second):
+		t.Fatal("close failed to wake reader")
+	}
+	b.setPacket(0, batchIP(4, 1))
+	if n := b.enqueue(h, 1, 24); n != errClosed {
+		t.Fatalf("enqueue after close = %d", n)
+	}
+}
+
+func TestBatchConcurrentProducersAndClose(t *testing.T) {
+	h, d := registerBatchDevice(t)
+	var wg sync.WaitGroup
+	for worker := 0; worker < 4; worker++ {
+		wg.Add(1)
+		go func() {
+			defer wg.Done()
+			b := newNativeBatch(32, 64)
+			defer b.free()
+			for i := range b.packets {
+				b.setPacket(i, batchIP(4, byte(i)))
+			}
+			for i := 0; i < 100; i++ {
+				n := b.enqueue(h, 32, 24)
+				if n != 32 && n != errClosed {
+					t.Errorf("race result %d", n)
+					return
+				}
+			}
+		}()
+	}
+	time.Sleep(time.Millisecond)
+	d.close()
+	wg.Wait()
+	if len(d.outbound) != 0 {
+		t.Fatal("enqueue resurrected closed queue")
+	}
+}
+
+func TestBatchPublicCloseRetiresHandleWhileReadWaits(t *testing.T) {
+	fd, peer, file := loopbackPair(t)
+	defer peer.Close()
+	defer file.Close()
+	tunnel, err := openWinn3(encode(t, baseConfig(t)), fd)
+	if err != nil {
+		t.Fatal(err)
+	}
+	h := nextHandle.Add(1)
+	winn3Mu.Lock()
+	winn3Registry[h] = tunnel
+	winn3Mu.Unlock()
+	defer nativeClose(h)
+	b := newNativeBatch(1, 64)
+	defer b.free()
+	done := make(chan int, 1)
+	go func() { done <- b.dequeue(h, 1, 24, 0) }()
+	time.Sleep(10 * time.Millisecond)
+	nativeClose(h)
+	select {
+	case n := <-done:
+		if n != errClosed && n != errHandle {
+			t.Fatalf("close result %d", n)
+		}
+	case <-time.After(time.Second):
+		t.Fatal("public close stranded reader")
+	}
+	if n := b.dequeue(h, 1, 24, 1); n != errHandle {
+		t.Fatalf("retired handle = %d", n)
+	}
+}
```

### winn_protocol_experimental/cdatapath/winn_packet_batch.h

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/cdatapath/winn_packet_batch.h
@@ -0,0 +1,26 @@
+#ifndef WINS_WINN3_PACKET_BATCH_H
+#define WINS_WINN3_PACKET_BATCH_H
+#include <stddef.h>
+#include <stdint.h>
+
+/* Apple 64-bit ABI. All integers are in host byte order. */
+#define WINS_WINN3_BATCH_MAX 32
+#define WINS_WINN3_PACKET_STRIDE 24
+#define WINS_WINN3_PACKET_MAX 65535
+
+typedef struct WinsWinn3PacketDescriptor {
+  void *data;
+  uint32_t length;
+  uint32_t capacity;
+  uint32_t family;
+  uint32_t reserved;
+} WinsWinn3PacketDescriptor;
+
+#if defined(__cplusplus)
+static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
+static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
+#else
+_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
+_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
+#endif
+#endif
```

### winn_protocol_experimental/cmd/winn-datapath/winn3_keys.go

<!-- winn345-patch:diff -->
```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_keys.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_keys.go
@@ -2,7 +2,6 @@
 
 import (
 	"bytes"
-	"encoding/hex"
 	"encoding/json"
 	"errors"
 	"fmt"
@@ -10,7 +9,7 @@
 
 	"winsvpn.local/winnprotocol/internal/securefile"
 	"winsvpn.local/winnprotocol/winn3/core"
-	"winsvpn.local/winnprotocol/winn3/dualsign"
+	"winsvpn.local/winnprotocol/winn3/hostqueue"
 	"winsvpn.local/winnprotocol/winn3/session"
 )
 
@@ -277,54 +276,15 @@
 }
 
 func readPrivateKeyFile(path, field string) ([]byte, error) {
-	raw, err := securefile.ReadPrivateLimited(path, winn3KeyFileMaxBytes)
-	if err != nil {
-		return nil, fmt.Errorf("%s: %w", field, err)
-	}
-	return raw, nil
+	return hostqueue.ReadPrivateKeyFile(path, field)
 }
 
 func applyDualAuthPublics(cfg *session.Config, edPath, mlPath string) error {
-	edPath = strings.TrimSpace(edPath)
-	mlPath = strings.TrimSpace(mlPath)
-	if (edPath == "") != (mlPath == "") {
-		return fmt.Errorf(
-			"dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path must be set together")
-	}
-	if edPath == "" {
-		return nil
-	}
-	edPub, err := readDualAuthPublic(
-		edPath, dualsign.Ed25519PublicKeySize, "dual_auth_ed25519_pub_path")
-	if err != nil {
-		return err
-	}
-	mlPub, err := readDualAuthPublic(
-		mlPath, dualsign.MLDSA65PublicKeySize, "dual_auth_mldsa65_pub_path")
-	if err != nil {
-		return err
-	}
-	cfg.DualAuth = session.DualAuthConfig{
-		Expected:      true,
-		Ed25519Public: edPub,
-		MLDSA65Public: mlPub,
-	}
-	return nil
+	return hostqueue.ApplyDualAuthPublics(cfg, edPath, mlPath)
 }
 
 func readDualAuthPublic(path string, want int, field string) ([]byte, error) {
-	raw, err := readPrivateKeyFile(path, field)
-	if err != nil {
-		return nil, err
-	}
-	decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
-	if err != nil {
-		return nil, fmt.Errorf("%s: %w", field, err)
-	}
-	if len(decoded) != want {
-		return nil, fmt.Errorf("%s: got %d bytes, want %d", field, len(decoded), want)
-	}
-	return decoded, nil
+	return hostqueue.ReadDualAuthPublic(path, want, field)
 }
 
 // winn3ReadKeyFile reads a 32-byte X25519 key in either accepted encoding.
@@ -332,24 +292,5 @@
 // Raw or hex, because the two provisioning paths in this tree disagree and
 // making the host convert would put key material through a shell.
 func winn3ReadKeyFile(path, field string) ([]byte, error) {
-	raw, err := readPrivateKeyFile(path, field)
-	if err != nil {
-		return nil, err
-	}
-	trimmed := bytes.TrimSpace(raw)
-	if len(trimmed) == hex.EncodedLen(core.KeySize) {
-		decoded, decodeErr := hex.DecodeString(string(trimmed))
-		if decodeErr == nil {
-			return decoded, nil
-		}
-	}
-	if len(raw) == core.KeySize {
-		return raw, nil
-	}
-	if len(trimmed) == core.KeySize {
-		return trimmed, nil
-	}
-	return nil, fmt.Errorf(
-		"%s: %d bytes; expected %d raw bytes or %d hex characters",
-		field, len(raw), core.KeySize, hex.EncodedLen(core.KeySize))
-}
+	return hostqueue.ReadKeyFile(path, field)
+}
```

### winn_protocol_experimental/winn3/carrier/batch.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch.go
@@ -0,0 +1,104 @@
+package carrier
+
+import (
+	"context"
+	"errors"
+	"net/netip"
+)
+
+const (
+	MaxBatchSize = 32
+	BatchSize    = MaxBatchSize
+	// MaxBatchBuffers bounds scatter/gather metadata for one datagram.
+	MaxBatchBuffers = 16
+	maxUDPAggregate = 65507
+	// Current Linux UDP_MAX_SEGMENTS is 128. Send batches remain at most 32.
+	maxGROSegments = 128
+)
+
+// BatchMsg is one complete datagram. Buffers are scatter/gather pieces of that
+// datagram, not separate messages. The caller owns all buffers; they must not
+// overlap other slots or be modified until IO returns. Receive accepts
+// negotiated-size slots; datagrams exceeding the destination slot are dropped
+// rather than truncated. Each slot must have nonzero total buffer length. N, Addr, Flags,
+// SegmentSize and Segments are outputs on receive. SegmentSize and Segments
+// describe the original GRO aggregate; each returned slot still requires its
+// own authentication. On send zero Addr selects the peer; a different address
+// is rejected. Flags and segmentation metadata are never syscall input.
+// Send updates N only for the committed prefix. No buffer is retained on send.
+type BatchMsg struct {
+	Buffers     [][]byte
+	Addr        netip.AddrPort
+	Flags       int
+	N           int
+	SegmentSize int
+	Segments    int
+}
+
+// BatchCarrier is optional and leaves Conn compatibility intact. Implemented
+// by UDP on Linux (including Android) and Darwin. Send returns only a committed
+// input prefix. The caller must retry only the suffix, including when err is
+// non-nil. Recv returns a compact prefix of complete peer datagrams. Truncated,
+// empty, oversized and malformed aggregate input is dropped, never delivered.
+// Empty batches succeed; batches above MaxBatchSize are invalid.
+type BatchCarrier interface {
+	RecvBatch(context.Context, []BatchMsg) (int, error)
+	SendBatch(context.Context, []BatchMsg) (int, error)
+}
+
+// LifetimeBinder binds a newly created socket generation before IO starts.
+// A successful binding is permanent for this carrier instance. Every later IO
+// must use the identical context, not a derived context. Migration needs a new
+// carrier instance; rebinding the same instance is refused before mutation.
+// With caller-owned reusable batch buffers, successful bound IO has no Go heap
+// allocations after initialization. Unbound per-operation contexts still work.
+type LifetimeBinder interface {
+	BindLifetime(context.Context) error
+}
+
+var (
+	ErrLifetimeBound   = errors.New("winn3/carrier: socket generation already bound")
+	ErrLifetimeContext = errors.New("winn3/carrier: IO context differs from bound lifetime")
+	ErrBatchSize       = errors.New("winn3/carrier: invalid batch or scatter/gather size")
+	ErrBatchPeer       = errors.New("winn3/carrier: batch destination differs from peer")
+)
+
+func batchBytes(buffers [][]byte) (int, error) {
+	if len(buffers) == 0 || len(buffers) > MaxBatchBuffers {
+		return 0, ErrBatchSize
+	}
+	n := 0
+	for _, b := range buffers {
+		if len(b) > maxUDPAggregate-n {
+			return 0, ErrMessageTooLarge
+		}
+		n += len(b)
+	}
+	return n, nil
+}
+
+func peerEqual(a, b netip.AddrPort) bool {
+	return a.Port() == b.Port() && a.Addr().Unmap().WithZone("") == b.Addr().Unmap().WithZone("")
+}
+
+func batchCapacity(buffers [][]byte) int {
+	n := 0
+	for _, b := range buffers {
+		if len(b) >= maxRecvDatagram-n {
+			return maxRecvDatagram
+		}
+		n += len(b)
+	}
+	return n
+}
+
+func putBatch(m *BatchMsg, data []byte, ap netip.AddrPort, flags, size, parts int) {
+	m.N, m.Addr, m.Flags, m.SegmentSize, m.Segments = len(data), ap, flags, size, parts
+	for _, buf := range m.Buffers {
+		n := copy(buf, data)
+		data = data[n:]
+		if len(data) == 0 {
+			break
+		}
+	}
+}
```

### winn_protocol_experimental/winn3/carrier/batch_darwin.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_darwin.go
@@ -0,0 +1,49 @@
+//go:build darwin
+
+package carrier
+
+import (
+	"runtime"
+	"syscall"
+	"unsafe"
+
+	"golang.org/x/sys/unix"
+)
+
+func batchSyscall(fd uintptr, s *batchIO) (int, error) {
+	trap := uintptr(unix.SYS_SENDMSG)
+	if s.read {
+		trap = unix.SYS_RECVMSG
+	}
+	for i := 0; i < s.count; {
+		n, _, errno := unix.Syscall(trap, fd, uintptr(unsafe.Pointer(&s.hdr[i].Hdr)), unix.MSG_DONTWAIT)
+		runtime.KeepAlive(s)
+		if errno == unix.EINTR {
+			continue
+		}
+		if errno != 0 {
+			if i > 0 && (errno == unix.EAGAIN || errno == unix.EWOULDBLOCK) {
+				return i, nil
+			}
+			return i, errno
+		}
+		s.hdr[i].Len = uint32(n)
+		i++
+	}
+	return s.count, nil
+}
+
+func enableBatchOffload(syscall.RawConn, bool) (bool, bool) { return false, false }
+func offloadUnsupported(error) bool                         { return false }
+func setSegmentControl(*unix.Msghdr, []byte, int)           {}
+func parseSegmentControl(buf []byte) (int, bool) {
+	// Darwin has no UDP_GRO in this backend. MSG_CTRUNC is rejected by the
+	// caller; ordinary ancillary records carry no segmentation authority.
+	return 0, true
+}
+func setBatchFamily4(a *unix.RawSockaddrInet4) {
+	a.Family, a.Len = unix.AF_INET, unix.SizeofSockaddrInet4
+}
+func setBatchFamily6(a *unix.RawSockaddrInet6) {
+	a.Family, a.Len = unix.AF_INET6, unix.SizeofSockaddrInet6
+}
```

### winn_protocol_experimental/winn3/carrier/batch_linux.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_linux.go
@@ -0,0 +1,106 @@
+//go:build linux
+
+package carrier
+
+import (
+	"encoding/binary"
+	"runtime"
+	"syscall"
+	"unsafe"
+
+	"golang.org/x/sys/unix"
+)
+
+func batchSyscall(fd uintptr, s *batchIO) (int, error) {
+	if !s.noMmsg {
+		trap := uintptr(unix.SYS_SENDMMSG)
+		if s.read {
+			trap = unix.SYS_RECVMMSG
+		}
+		n, _, errno := unix.Syscall6(trap, fd, uintptr(unsafe.Pointer(&s.hdr[0])), uintptr(s.count), unix.MSG_DONTWAIT, 0, 0)
+		runtime.KeepAlive(s)
+		if errno == 0 {
+			return int(n), nil
+		}
+		if errno != unix.ENOSYS {
+			return 0, errno
+		}
+		s.noMmsg = true
+	}
+	// A kernel/seccomp ENOSYS rejection is a capability failure before any
+	// datagram was committed. Fall back to exactly one message, never replay.
+	trap := uintptr(unix.SYS_SENDMSG)
+	if s.read {
+		trap = unix.SYS_RECVMSG
+	}
+	n, _, errno := unix.Syscall(trap, fd, uintptr(unsafe.Pointer(&s.hdr[0].Hdr)), unix.MSG_DONTWAIT)
+	runtime.KeepAlive(s)
+	if errno != 0 {
+		return 0, errno
+	}
+	s.hdr[0].Len = uint32(n)
+	return 1, nil
+}
+
+func enableBatchOffload(raw syscall.RawConn, enabled bool) (gro, gso bool) {
+	if !enabled {
+		return false, false
+	}
+	err := raw.Control(func(fd uintptr) {
+		gro = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1) == nil
+		_, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
+		gso = e == nil
+	})
+	if err != nil {
+		return false, false
+	}
+	return gro, gso
+}
+
+func offloadUnsupported(err error) bool {
+	return err == unix.EINVAL || err == unix.ENOPROTOOPT || err == unix.EOPNOTSUPP || err == unix.EMSGSIZE || err == unix.EIO || err == unix.ENOSYS
+}
+
+func setSegmentControl(h *unix.Msghdr, buf []byte, size int) {
+	clear(buf)
+	c := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
+	c.Level, c.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
+	c.SetLen(unix.CmsgLen(2))
+	binary.NativeEndian.PutUint16(buf[unix.CmsgLen(0):], uint16(size))
+	h.Control = &buf[0]
+	h.SetControllen(unix.CmsgSpace(2))
+}
+
+// Linux UDP_GRO carries an int segment size, whereas UDP_SEGMENT uses uint16.
+// Parse in place, reject duplicate/malformed metadata and never allocate the
+// []SocketControlMessage that unix.ParseSocketControlMessage would construct.
+func parseSegmentControl(buf []byte) (segment int, ok bool) {
+	header := unix.CmsgLen(0)
+	for len(buf) >= header {
+		c := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
+		n := int(c.Len)
+		if n < header || n > len(buf) {
+			return 0, false
+		}
+		if c.Level == unix.IPPROTO_UDP && c.Type == unix.UDP_GRO {
+			if segment != 0 || n != unix.CmsgLen(4) {
+				return 0, false
+			}
+			size := binary.NativeEndian.Uint32(buf[header:n])
+			if size == 0 || size > maxUDPAggregate {
+				return 0, false
+			}
+			segment = int(size)
+		}
+		step := unix.CmsgSpace(n - header)
+		if step > len(buf) {
+			// The final cmsg can legally omit its alignment padding.
+			return segment, n == len(buf)
+		}
+		buf = buf[step:]
+	}
+	return segment, len(buf) == 0
+}
+
+func setBatchFamily4(a *unix.RawSockaddrInet4) { a.Family = unix.AF_INET }
+func setBatchFamily6(a *unix.RawSockaddrInet6) { a.Family = unix.AF_INET6 }
```

### winn_protocol_experimental/winn3/carrier/batch_linux_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_linux_test.go
@@ -0,0 +1,373 @@
+//go:build linux
+
+package carrier
+
+import (
+	"bytes"
+	"context"
+	"crypto/aes"
+	"crypto/cipher"
+	"encoding/binary"
+	"errors"
+	"net/netip"
+	"testing"
+	"unsafe"
+
+	"golang.org/x/sys/unix"
+)
+
+func TestBatchLinuxMmsgABI(t *testing.T) {
+	if unsafe.Sizeof(mmsg{}) != 64 || unsafe.Offsetof(mmsg{}.Len) != 56 || unsafe.Sizeof(unix.Msghdr{}) != 56 {
+		t.Fatalf("unexpected 64-bit mmsghdr layout size=%d len-offset=%d", unsafe.Sizeof(mmsg{}), unsafe.Offsetof(mmsg{}.Len))
+	}
+}
+
+func TestBatchLinuxGSOExactAuthenticatedDatagrams(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, true)
+	ctx := bindPair(t, a, b)
+	if !a.batch.gso || !b.batch.gro {
+		t.Skipf("kernel offload unavailable: GSO=%v GRO=%v", a.batch.gso, b.batch.gro)
+	}
+	block, err := aes.NewCipher(make([]byte, 32))
+	if err != nil {
+		t.Fatal(err)
+	}
+	aead, err := cipher.NewGCM(block)
+	if err != nil {
+		t.Fatal(err)
+	}
+	sizes := []int{800, 800, 123, 1000, 1000, 1000, 55, 200, 201, 700, 700, 99}
+	send := make([]BatchMsg, len(sizes))
+	want := make([][]byte, len(sizes))
+	plain := make([][]byte, len(sizes))
+	for i, n := range sizes {
+		nonce := make([]byte, aead.NonceSize())
+		binary.BigEndian.PutUint64(nonce[4:], uint64(i))
+		plain[i] = bytes.Repeat([]byte{byte(i + 1)}, n-aead.NonceSize()-aead.Overhead())
+		want[i] = aead.Seal(nonce, nonce, plain[i], nil)
+		if i == 4 {
+			want[i][len(want[i])-1] ^= 1
+		}
+		send[i].Buffers = [][]byte{want[i][:17], want[i][17:]}
+	}
+	sendAllBatch(t, a, ctx, send)
+	if !a.batch.gso {
+		t.Fatal("live GSO test fell back")
+	}
+	recv := receiveSlots(1, b.MaxMessageSize())
+	sawGRO := false
+	for i := range send {
+		n, err := b.RecvBatch(ctx, recv)
+		if n != 1 || err != nil {
+			t.Fatalf("datagram %d: %d %v", i, n, err)
+		}
+		got := flattenBatch(recv[0])
+		if !bytes.Equal(got, want[i]) {
+			t.Fatalf("datagram %d boundary changed", i)
+		}
+		if recv[0].Segments > 1 {
+			sawGRO = true
+		}
+		opened, e := aead.Open(nil, got[:aead.NonceSize()], got[aead.NonceSize():], nil)
+		if i == 4 {
+			if e == nil {
+				t.Fatal("tampered independent record authenticated")
+			}
+		} else if e != nil || !bytes.Equal(opened, plain[i]) {
+			t.Fatalf("record %d did not authenticate independently: %v", i, e)
+		}
+	}
+	if !sawGRO {
+		t.Fatal("no actual GRO metadata observed")
+	}
+	if b.Stats().Delivered != uint64(len(send)) {
+		t.Fatalf("arrival stats %+v", b.Stats())
+	}
+}
+
+func TestBatchLinuxGSOFallbackAndPartialPrefix(t *testing.T) {
+	for _, partial := range []bool{false, true} {
+		t.Run(map[bool]string{false: "unsupported", true: "partial"}[partial], func(t *testing.T) {
+			a, b, _, _ := newBatchPair(t, true, true)
+			ctx := bindPair(t, a, b)
+			if !a.batch.gso {
+				t.Skip("kernel GSO unavailable")
+			}
+			original := a.batch.tx.callback
+			s := &a.batch.tx
+			calls := 0
+			s.callback = func(fd uintptr) bool {
+				calls++
+				if calls == 1 {
+					if partial {
+						count := s.count
+						s.count = 1
+						done := original(fd)
+						s.count = count
+						if s.n > 0 {
+							s.err = unix.EIO
+						}
+						return done
+					}
+					s.n, s.err = 0, unix.EIO
+					return true
+				}
+				return original(fd)
+			}
+			m := []BatchMsg{{Buffers: [][]byte{bytes.Repeat([]byte{1}, 300)}}, {Buffers: [][]byte{bytes.Repeat([]byte{2}, 300)}}, {Buffers: [][]byte{bytes.Repeat([]byte{3}, 99)}}, {Buffers: [][]byte{bytes.Repeat([]byte{4}, 500)}}}
+			n, err := a.SendBatch(ctx, m)
+			if partial {
+				if n != 3 || !errors.Is(err, unix.EIO) || calls != 1 {
+					t.Fatalf("partial group prefix %d %v calls=%d", n, err, calls)
+				}
+				if !a.batch.gso {
+					t.Fatal("partial success triggered replay fallback")
+				}
+				s.callback = original
+				sendAllBatch(t, a, ctx, m[n:])
+			} else if n != 4 || err != nil || calls != 2 || a.batch.gso {
+				t.Fatalf("fallback %d %v calls=%d GSO=%v", n, err, calls, a.batch.gso)
+			}
+			recv := receiveSlots(4, b.MaxMessageSize())
+			at := 0
+			for at < 4 {
+				n, err = b.RecvBatch(ctx, recv[:4-at])
+				if err != nil {
+					t.Fatal(err)
+				}
+				for i := 0; i < n; i++ {
+					if !bytes.Equal(flattenBatch(recv[i]), m[at+i].Buffers[0]) {
+						t.Fatal("prefix replayed or boundary changed")
+					}
+				}
+				at += n
+			}
+			if a.Stats().Sent != 4 || b.Stats().Delivered != 4 {
+				t.Fatalf("counters %+v %+v", a.Stats(), b.Stats())
+			}
+		})
+	}
+}
+
+func TestBatchLinuxGSOPackingLimits(t *testing.T) {
+	a, _, _, _ := newBatchPair(t, true, false)
+	a.batch.gso = true
+	cases := [][]int{make([]int, 32), make([]int, 32), {1000, 1000, 99, 1200, 400, 401, 401, 1}, {65507, 1}}
+	for i := range cases[0] {
+		cases[0][i] = 2048
+		cases[1][i] = 2048
+	}
+	cases[1][31] = 2019
+	for ci, sizes := range cases {
+		msgs := make([]BatchMsg, len(sizes))
+		for i, n := range sizes {
+			msgs[i].Buffers = [][]byte{make([]byte, n)}
+			a.batch.tx.lengths[i] = n
+		}
+		if err := a.packSend(msgs, a.Peer().AddrPort(), true); err != nil {
+			t.Fatal(err)
+		}
+		s := &a.batch.tx
+		at := 0
+		for i := 0; i < s.count; i++ {
+			total := 0
+			for j := 0; j < s.groups[i]; j++ {
+				n := sizes[at+j]
+				total += n
+				if j > 0 && n > sizes[at] {
+					t.Fatal("segment exceeds group size")
+				}
+				if j < s.groups[i]-1 && n != sizes[at] {
+					t.Fatal("short middle segment")
+				}
+			}
+			if total > 65507 || s.groups[i] > 32 {
+				t.Fatalf("unbounded group %d/%d", total, s.groups[i])
+			}
+			at += s.groups[i]
+		}
+		if at != len(sizes) {
+			t.Fatal("lost datagram")
+		}
+		if ci == 0 && s.count != 2 {
+			t.Fatalf("65536-byte batch groups %d", s.count)
+		}
+		if ci == 1 && s.count != 1 {
+			t.Fatalf("65507-byte batch groups %d", s.count)
+		}
+		clear(s.iov[:])
+	}
+}
+
+func groControl(buf []byte, size uint32) int {
+	clear(buf)
+	c := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
+	c.Level, c.Type = unix.IPPROTO_UDP, unix.UDP_GRO
+	c.SetLen(unix.CmsgLen(4))
+	binary.NativeEndian.PutUint32(buf[unix.CmsgLen(0):], size)
+	return unix.CmsgSpace(4)
+}
+
+func TestBatchLinuxGROMalformedControl(t *testing.T) {
+	var aligned [64]byte
+	n := groControl(aligned[:], 800)
+	if got, ok := parseSegmentControl(aligned[:n]); !ok || got != 800 {
+		t.Fatalf("valid GRO %d %v", got, ok)
+	}
+	for _, size := range []uint32{0, 65508, 0xffffffff} {
+		n = groControl(aligned[:], size)
+		if _, ok := parseSegmentControl(aligned[:n]); ok {
+			t.Fatalf("accepted size %d", size)
+		}
+	}
+	n = groControl(aligned[:], 100)
+	copy(aligned[n:], aligned[:n])
+	if _, ok := parseSegmentControl(aligned[:n*2]); ok {
+		t.Fatal("duplicate metadata accepted")
+	}
+	n = groControl(aligned[:], 100)
+	c := (*unix.Cmsghdr)(unsafe.Pointer(&aligned[0]))
+	c.SetLen(unix.CmsgLen(2))
+	if _, ok := parseSegmentControl(aligned[:n]); ok {
+		t.Fatal("uint16 GRO accepted; Linux sends int")
+	}
+	c.SetLen(999)
+	if _, ok := parseSegmentControl(aligned[:n]); ok {
+		t.Fatal("out of bounds cmsg accepted")
+	}
+}
+
+func TestBatchLinuxGRODropsTruncatedAndInvalidAggregates(t *testing.T) {
+	for _, kind := range []string{"trunc", "ctrunc", "count", "overmax", "control-length"} {
+		t.Run(kind, func(t *testing.T) {
+			a, b, _, _ := newBatchPair(t, true, true)
+			ctx := bindPair(t, a, b)
+			if !b.batch.gro {
+				t.Skip("kernel GRO unavailable")
+			}
+			s := &b.batch.rx
+			original := s.callback
+			calls := 0
+			s.callback = func(fd uintptr) bool {
+				calls++
+				if calls != 1 {
+					return original(fd)
+				}
+				n, err := marshalBatchAddr(&s.addr[0], b.Peer().AddrPort())
+				if err != nil {
+					t.Fatal(err)
+				}
+				s.hdr[0].Hdr.Namelen = uint32(n)
+				s.hdr[0].Len = 129
+				control := groControl(s.control[0][:], 1)
+				s.hdr[0].Hdr.SetControllen(control)
+				switch kind {
+				case "trunc":
+					s.hdr[0].Hdr.Flags = unix.MSG_TRUNC
+				case "ctrunc":
+					s.hdr[0].Hdr.Flags = unix.MSG_CTRUNC
+				case "overmax":
+					s.hdr[0].Len = 65508
+				case "control-length":
+					s.hdr[0].Hdr.SetControllen(4096)
+				}
+				s.n, s.err = 1, nil
+				return true
+			}
+			if err := a.Send(ctx, []byte("valid after drop")); err != nil {
+				t.Fatal(err)
+			}
+			m := receiveSlots(1, b.MaxMessageSize())
+			n, err := b.RecvBatch(ctx, m)
+			if n != 1 || err != nil || string(flattenBatch(m[0])) != "valid after drop" {
+				t.Fatalf("drop recovery %d %v", n, err)
+			}
+			if b.Stats().Delivered != 1 || b.Stats().RecvErrors != 1 {
+				t.Fatalf("invalid aggregate moved delivery %+v", b.Stats())
+			}
+		})
+	}
+}
+
+func TestBatchLinuxMmsgCapabilityFallback(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, false)
+	ctx := bindPair(t, a, b)
+	a.batch.tx.noMmsg, b.batch.rx.noMmsg = true, true
+	m := []BatchMsg{{Buffers: [][]byte{[]byte("one")}}, {Buffers: [][]byte{[]byte("two")}}}
+	n, err := a.SendBatch(ctx, m)
+	if n != 1 || err != nil {
+		t.Fatalf("fallback send %d %v", n, err)
+	}
+	recv := receiveSlots(2, b.MaxMessageSize())
+	n, err = b.RecvBatch(ctx, recv)
+	if n != 1 || err != nil || string(flattenBatch(recv[0])) != "one" {
+		t.Fatalf("fallback recv %d %v", n, err)
+	}
+}
+
+func TestBatchLinuxGROPendingArrivalAndPeerMigration(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, true)
+	ctx := bindPair(t, a, b)
+	if !a.batch.gso || !b.batch.gro {
+		t.Skip("offload unavailable")
+	}
+	m := []BatchMsg{{Buffers: [][]byte{bytes.Repeat([]byte{1}, 100)}}, {Buffers: [][]byte{bytes.Repeat([]byte{2}, 100)}}, {Buffers: [][]byte{bytes.Repeat([]byte{3}, 100)}}}
+	sendAllBatch(t, a, ctx, m)
+	recv := receiveSlots(1, b.MaxMessageSize())
+	n, err := b.RecvBatch(ctx, recv)
+	if n != 1 || err != nil || b.batch.pendingN == 0 {
+		t.Fatalf("GRO did not leave pending segments: %d %v", n, err)
+	}
+	if b.Stats().Delivered != 3 {
+		t.Fatalf("arrival postponed until caller drained: %+v", b.Stats())
+	}
+	// This is a test-only authenticated-migration stand-in. SetPeer itself
+	// remains callable only after session authentication in the real driver.
+	newPeer := netip.MustParseAddrPort("127.0.0.1:1")
+	p := b.Peer()
+	p.Port = int(newPeer.Port())
+	if err = b.SetPeer(p); err != nil {
+		t.Fatal(err)
+	}
+	if n = b.drainGRO(recv, b.MaxMessageSize()); n != 0 || b.batch.pendingN != 0 || b.Stats().Foreign != 2 {
+		t.Fatalf("old peer queue escaped migration n=%d stats=%+v", n, b.Stats())
+	}
+}
+
+func BenchmarkBatchLinuxOffloadRoundTrip(b *testing.B) {
+	a, c, _, _ := newBatchPair(b, true, true)
+	if !a.batch.gso || !c.batch.gro {
+		b.Skip("kernel offload unavailable")
+	}
+	ctx := context.Background()
+	if err := a.BindLifetime(ctx); err != nil {
+		b.Fatal(err)
+	}
+	if err := c.BindLifetime(ctx); err != nil {
+		b.Fatal(err)
+	}
+	send := make([]BatchMsg, 32)
+	for i := range send {
+		send[i].Buffers = [][]byte{make([]byte, 1024)}
+	}
+	recv := receiveSlots(32, c.MaxMessageSize())
+	b.ReportAllocs()
+	b.SetBytes(32768)
+	b.ResetTimer()
+	for i := 0; i < b.N; i++ {
+		for at := 0; at < 32; {
+			n, e := a.SendBatch(ctx, send[at:])
+			if e != nil {
+				b.Fatal(e)
+			}
+			at += n
+		}
+		for at := 0; at < 32; {
+			n, e := c.RecvBatch(ctx, recv[:32-at])
+			if e != nil {
+				b.Fatal(e)
+			}
+			at += n
+		}
+	}
+}
```

### winn_protocol_experimental/winn3/carrier/batch_other.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_other.go
@@ -0,0 +1,21 @@
+//go:build !linux && !darwin
+
+package carrier
+
+import (
+	"context"
+	"net"
+)
+
+// Platforms without the reviewed raw datagram backend keep the existing Conn
+// implementation and do not advertise BatchCarrier or LifetimeBinder.
+type udpBatch struct{}
+
+func (u *UDP) initBatch(bool) error                               { return nil }
+func (u *UDP) closeBatch()                                        {}
+func (u *UDP) platformSend(context.Context, []byte) (bool, error) { return false, nil }
+func (u *UDP) platformRecv(context.Context, []byte) (bool, []byte, error) {
+	return false, nil, nil
+}
+
+func (u *UDP) setBatchPeer(*net.UDPAddr) error { return nil }
```

### winn_protocol_experimental/winn3/carrier/batch_pipe.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_pipe.go
@@ -0,0 +1,162 @@
+package carrier
+
+import (
+	"context"
+	"io"
+	"net/netip"
+	"sync"
+)
+
+// BatchPipe explicitly opts a queue carrier into batching. NewPipe deliberately
+// remains scalar: adding batch methods to Pipe would bypass Send/Recv overrides
+// on existing wrappers through Go method promotion. This wrapper batches queue
+// work only; a gateway callback still performs its ordinary socket writes.
+type BatchPipe struct {
+	*Pipe
+	recvMu     sync.Mutex
+	sendMu     sync.Mutex
+	pending    []byte
+	sendBuffer []byte
+}
+
+func NewBatchPipe(cfg PipeConfig) (*BatchPipe, error) {
+	p, err := NewPipe(cfg)
+	if err != nil {
+		return nil, err
+	}
+	return &BatchPipe{Pipe: p, sendBuffer: make([]byte, min(p.pathCeiling, maxUDPAggregate))}, nil
+}
+
+func (p *BatchPipe) Send(ctx context.Context, msg []byte) error {
+	p.sendMu.Lock()
+	defer p.sendMu.Unlock()
+	return p.Pipe.Send(ctx, msg)
+}
+
+func (p *BatchPipe) SendBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
+	p.sendMu.Lock()
+	defer p.sendMu.Unlock()
+	if ctx == nil {
+		return 0, ErrConfig
+	}
+	if err := ctx.Err(); err != nil {
+		return 0, err
+	}
+	if len(msgs) > MaxBatchSize {
+		return 0, ErrBatchSize
+	}
+	ceiling := p.MaxMessageSize()
+	for i := range msgs {
+		msgs[i].N = 0
+		n, err := batchBytes(msgs[i].Buffers)
+		if err != nil {
+			return 0, err
+		}
+		if n == 0 {
+			return 0, ErrMessageEmpty
+		}
+		if n > ceiling || n > len(p.sendBuffer) {
+			return 0, ErrMessageTooLarge
+		}
+		if msgs[i].Addr.IsValid() {
+			return 0, ErrBatchPeer
+		}
+	}
+	for i := range msgs {
+		n := 0
+		for _, buf := range msgs[i].Buffers {
+			n += copy(p.sendBuffer[n:], buf)
+		}
+		if err := p.Pipe.Send(ctx, p.sendBuffer[:n]); err != nil {
+			return i, err
+		}
+		msgs[i].N = n
+	}
+	return len(msgs), nil
+}
+
+func (p *BatchPipe) Recv(ctx context.Context) ([]byte, error) {
+	p.recvMu.Lock()
+	defer p.recvMu.Unlock()
+	if err := p.recvReady(ctx); err != nil {
+		return nil, err
+	}
+	if p.pending != nil {
+		msg := p.pending
+		p.pending = nil
+		return msg, nil
+	}
+	return p.Pipe.Recv(ctx)
+}
+
+func (p *BatchPipe) recvReady(ctx context.Context) error {
+	if ctx == nil {
+		return ErrConfig
+	}
+	if err := ctx.Err(); err != nil {
+		return err
+	}
+	select {
+	case <-p.done:
+		return ErrClosed
+	default:
+		return nil
+	}
+}
+
+// RecvBatch blocks for the first message and then drains only immediately ready
+// queue entries. Arrival/flow counters remain exclusively in Pipe.Deliver. A
+// short destination returns its completed prefix and io.ErrShortBuffer, keeping
+// the next queued message for a larger retry or scalar Recv. Slots are copied;
+// the caller never borrows queue backing storage through this method.
+func (p *BatchPipe) RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
+	p.recvMu.Lock()
+	defer p.recvMu.Unlock()
+	if err := p.recvReady(ctx); err != nil {
+		return 0, err
+	}
+	if len(msgs) > MaxBatchSize {
+		return 0, ErrBatchSize
+	}
+	for i := range msgs {
+		if len(msgs[i].Buffers) == 0 || len(msgs[i].Buffers) > MaxBatchBuffers {
+			return 0, ErrBatchSize
+		}
+		if batchCapacity(msgs[i].Buffers) == 0 {
+			return 0, io.ErrShortBuffer
+		}
+		msgs[i].N, msgs[i].Flags, msgs[i].SegmentSize, msgs[i].Segments = 0, 0, 0, 0
+		msgs[i].Addr = netip.AddrPort{}
+	}
+	for i := range msgs {
+		if err := p.recvReady(ctx); err != nil {
+			return i, err
+		}
+		msg := p.pending
+		if msg == nil {
+			if i == 0 {
+				var err error
+				msg, err = p.Pipe.Recv(ctx)
+				if err != nil {
+					return 0, err
+				}
+			} else {
+				select {
+				case msg = <-p.inbox:
+				default:
+					return i, nil
+				}
+			}
+		}
+		if len(msg) > batchCapacity(msgs[i].Buffers) {
+			p.pending = msg
+			return i, io.ErrShortBuffer
+		}
+		p.pending = nil
+		putBatch(&msgs[i], msg, netip.AddrPort{}, 0, 0, 1)
+	}
+	return len(msgs), nil
+}
+
+var _ Conn = (*BatchPipe)(nil)
+var _ BatchCarrier = (*BatchPipe)(nil)
```

### winn_protocol_experimental/winn3/carrier/batch_pipe_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_pipe_test.go
@@ -0,0 +1,118 @@
+package carrier
+
+import (
+	"context"
+	"errors"
+	"io"
+	"testing"
+	"time"
+)
+
+func TestBatchPipeIsExplicitAndPreservesArrivalFlow(t *testing.T) {
+	scalar, err := NewPipe(PipeConfig{Class: ClassUDP})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer scalar.Close()
+	if _, ok := any(scalar).(BatchCarrier); ok {
+		t.Fatal("scalar Pipe unexpectedly promotes batch methods")
+	}
+	p, err := NewBatchPipe(PipeConfig{Class: ClassUDP, Seq: func(b []byte) uint64 { return uint64(b[0]) }})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer p.Close()
+	for _, n := range []byte{1, 3, 2} {
+		if err = p.Deliver([]byte{n}); err != nil {
+			t.Fatal(err)
+		}
+	}
+	before, flow := p.Stats(), p.Flow()
+	if before.Delivered != 3 || flow.Reordered != 1 || flow.Lost != 1 {
+		t.Fatalf("arrival %+v flow %+v", before, flow)
+	}
+	msgs := make([]BatchMsg, 32)
+	for i := range msgs {
+		msgs[i].Buffers = [][]byte{make([]byte, 100)}
+	}
+	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
+	defer cancel()
+	n, err := p.RecvBatch(ctx, msgs)
+	if n != 3 || err != nil {
+		t.Fatalf("ready prefix %d %v", n, err)
+	}
+	for i, want := range []byte{1, 3, 2} {
+		if msgs[i].N != 1 || msgs[i].Buffers[0][0] != want {
+			t.Fatal("queue was reordered")
+		}
+	}
+	if p.Stats() != before || p.Flow() != flow {
+		t.Fatal("draining changed arrival counters")
+	}
+}
+
+func TestBatchPipeShortBufferPreservesQueueHeadAndSendPrefix(t *testing.T) {
+	failure := errors.New("sink refused second datagram")
+	calls := 0
+	p, err := NewBatchPipe(PipeConfig{Class: ClassUDP, Out: func(b []byte) error {
+		calls++
+		if calls == 2 {
+			return failure
+		}
+		return nil
+	}})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer p.Close()
+	m := []BatchMsg{{Buffers: [][]byte{[]byte("first")}}, {Buffers: [][]byte{[]byte("second")}}}
+	n, err := p.SendBatch(context.Background(), m)
+	if n != 1 || !errors.Is(err, failure) || m[1].N != 0 || p.Stats().Sent != 1 {
+		t.Fatalf("send prefix %d %v", n, err)
+	}
+	if err = p.Deliver([]byte("a")); err != nil {
+		t.Fatal(err)
+	}
+	if err = p.Deliver([]byte("keep whole")); err != nil {
+		t.Fatal(err)
+	}
+	recv := []BatchMsg{{Buffers: [][]byte{make([]byte, 2)}}, {Buffers: [][]byte{make([]byte, 2)}}}
+	n, err = p.RecvBatch(context.Background(), recv)
+	if n != 1 || !errors.Is(err, io.ErrShortBuffer) || string(recv[0].Buffers[0][:recv[0].N]) != "a" {
+		t.Fatalf("recv prefix %d %v", n, err)
+	}
+	msg, err := p.Recv(context.Background())
+	if err != nil || string(msg) != "keep whole" {
+		t.Fatalf("lost head %q %v", msg, err)
+	}
+	if p.Stats().Delivered != 2 {
+		t.Fatal("changed arrival counters")
+	}
+}
+
+func TestBatchPipeCancellationAndClose(t *testing.T) {
+	for _, closeIt := range []bool{false, true} {
+		p, err := NewBatchPipe(PipeConfig{Class: ClassUDP})
+		if err != nil {
+			t.Fatal(err)
+		}
+		ctx, cancel := context.WithCancel(context.Background())
+		result := make(chan error, 1)
+		go func() { _, err := p.RecvBatch(ctx, []BatchMsg{{Buffers: [][]byte{make([]byte, 100)}}}); result <- err }()
+		if closeIt {
+			p.Close()
+		} else {
+			cancel()
+		}
+		select {
+		case err := <-result:
+			if err == nil {
+				t.Fatal("blocked read returned success")
+			}
+		case <-time.After(time.Second):
+			t.Fatal("read did not unblock")
+		}
+		cancel()
+		p.Close()
+	}
+}
```

### winn_protocol_experimental/winn3/carrier/batch_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_test.go
@@ -0,0 +1,564 @@
+//go:build linux || darwin
+
+package carrier
+
+import (
+	"bytes"
+	"context"
+	"errors"
+	"io"
+	"net"
+	"net/netip"
+	"runtime"
+	"testing"
+	"time"
+
+	"golang.org/x/sys/unix"
+)
+
+func newBatchPair(t testing.TB, owns, offload bool) (*UDP, *UDP, *net.UDPConn, *net.UDPConn) {
+	t.Helper()
+	listen := func() *net.UDPConn {
+		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
+		if err != nil {
+			t.Fatal(err)
+		}
+		t.Cleanup(func() { c.Close() })
+		return c
+	}
+	a, b := listen(), listen()
+	wrap := func(c, peer *net.UDPConn) *UDP {
+		u, err := NewUDP(UDPConfig{Conn: c, Peer: peer.LocalAddr().(*net.UDPAddr), OwnsConn: owns, EnableUDPOffload: offload})
+		if err != nil {
+			t.Fatal(err)
+		}
+		t.Cleanup(func() { u.Close() })
+		return u
+	}
+	return wrap(a, b), wrap(b, a), a, b
+}
+
+func receiveSlots(n, size int) []BatchMsg {
+	m := make([]BatchMsg, n)
+	for i := range m {
+		m[i].Buffers = [][]byte{make([]byte, size/2), make([]byte, size-size/2)}
+	}
+	return m
+}
+
+func flattenBatch(m BatchMsg) []byte {
+	out := make([]byte, 0, m.N)
+	left := m.N
+	for _, b := range m.Buffers {
+		n := min(left, len(b))
+		out = append(out, b[:n]...)
+		left -= n
+	}
+	return out
+}
+
+func bindPair(t testing.TB, a, b *UDP) context.Context {
+	t.Helper()
+	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
+	t.Cleanup(cancel)
+	if err := a.BindLifetime(ctx); err != nil {
+		t.Fatal(err)
+	}
+	if err := b.BindLifetime(ctx); err != nil {
+		t.Fatal(err)
+	}
+	return ctx
+}
+
+func sendAllBatch(t testing.TB, u *UDP, ctx context.Context, m []BatchMsg) {
+	t.Helper()
+	for len(m) > 0 {
+		n, err := u.SendBatch(ctx, m)
+		if err != nil || n <= 0 {
+			t.Fatalf("send prefix=%d err=%v", n, err)
+		}
+
+		m = m[n:]
+	}
+}
+
+func TestBatchMixedScatterRoundTrip(t *testing.T) {
+	for _, owned := range []bool{false, true} {
+		t.Run(map[bool]string{false: "borrowed", true: "owned"}[owned], func(t *testing.T) {
+			a, b, _, _ := newBatchPair(t, owned, false)
+			ctx := bindPair(t, a, b)
+			send := make([]BatchMsg, MaxBatchSize)
+			want := make([][]byte, len(send))
+			total := 0
+			for i := range send {
+				want[i] = bytes.Repeat([]byte{byte(i + 1)}, 29+i*17)
+				send[i].Buffers = [][]byte{want[i][:11], want[i][11:]}
+				total += len(want[i])
+			}
+			sendAllBatch(t, a, ctx, send)
+			recv := receiveSlots(MaxBatchSize, b.MaxMessageSize())
+			at := 0
+			for at < len(send) {
+				n, err := b.RecvBatch(ctx, recv[:len(send)-at])
+				if err != nil || n <= 0 {
+					t.Fatalf("recv %d: %v", n, err)
+				}
+
+				for j := 0; j < n; j++ {
+					if !bytes.Equal(flattenBatch(recv[j]), want[at+j]) {
+						t.Fatalf("message %d changed", at+j)
+					}
+					if !peerEqual(recv[j].Addr, b.Peer().AddrPort()) {
+						t.Fatalf("source %v", recv[j].Addr)
+					}
+				}
+				at += n
+			}
+			if s := a.Stats(); s.Sent != 32 || s.SentBytes != uint64(total) {
+				t.Fatalf("send stats %+v", s)
+			}
+			if s := b.Stats(); s.Delivered != 32 || s.DeliveredBytes != uint64(total) || s.Foreign != 0 {
+				t.Fatalf("recv stats %+v", s)
+			}
+		})
+	}
+}
+
+func TestBatchForeignEmptyOversizeAndTruncation(t *testing.T) {
+	a, b, ac, bc := newBatchPair(t, true, false)
+	ctx := bindPair(t, a, b)
+	foreign, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer foreign.Close()
+	if _, err = foreign.WriteToUDP([]byte("foreign"), bc.LocalAddr().(*net.UDPAddr)); err != nil {
+		t.Fatal(err)
+	}
+	for _, bad := range [][]byte{nil, make([]byte, b.MaxMessageSize()+1), make([]byte, b.MaxMessageSize()*3)} {
+		if _, err = ac.WriteToUDP(bad, bc.LocalAddr().(*net.UDPAddr)); err != nil {
+			t.Fatal(err)
+		}
+	}
+	if err = a.Send(ctx, []byte("valid")); err != nil {
+		t.Fatal(err)
+	}
+	m := receiveSlots(8, b.MaxMessageSize())
+	n, err := b.RecvBatch(ctx, m)
+	if err != nil || n != 1 || string(flattenBatch(m[0])) != "valid" {
+		t.Fatalf("n=%d err=%v", n, err)
+	}
+	s := b.Stats()
+	if s.Delivered != 1 || s.Foreign != 1 || s.RecvErrors != 3 || s.PeerMoves != 0 {
+		t.Fatalf("stats %+v", s)
+	}
+}
+
+func TestBatchRefusalsDoNotConsumeOrSend(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, false)
+	ctx := bindPair(t, a, b)
+	if n, e := a.SendBatch(ctx, make([]BatchMsg, 33)); n != 0 || !errors.Is(e, ErrBatchSize) {
+		t.Fatalf("%d %v", n, e)
+	}
+	if n, e := b.RecvBatch(ctx, make([]BatchMsg, 33)); n != 0 || !errors.Is(e, ErrBatchSize) {
+		t.Fatalf("%d %v", n, e)
+	}
+	for _, m := range []BatchMsg{{Buffers: [][]byte{nil}}, {Buffers: [][]byte{make([]byte, a.MaxMessageSize()+1)}}, {Buffers: [][]byte{[]byte("a")}, Addr: netip.MustParseAddrPort("127.0.0.1:1")}, {Buffers: make([][]byte, 17)}} {
+		if n, e := a.SendBatch(ctx, []BatchMsg{m}); n != 0 || e == nil {
+			t.Fatalf("invalid send %d %v", n, e)
+		}
+	}
+	if n, e := a.SendBatch(ctx, nil); n != 0 || e != nil {
+		t.Fatalf("empty send %d %v", n, e)
+	}
+	if n, e := b.RecvBatch(ctx, nil); n != 0 || e != nil {
+		t.Fatalf("empty recv %d %v", n, e)
+	}
+	if err := a.Send(ctx, []byte("queued")); err != nil {
+		t.Fatal(err)
+	}
+	if n, e := b.RecvBatch(ctx, receiveSlots(1, 0)); n != 0 || !errors.Is(e, io.ErrShortBuffer) {
+		t.Fatalf("short receive %d %v", n, e)
+	}
+	m := receiveSlots(1, b.MaxMessageSize())
+	n, e := b.RecvBatch(ctx, m)
+	if n != 1 || e != nil || string(flattenBatch(m[0])) != "queued" {
+		t.Fatalf("short buffer consumed input %d %v", n, e)
+	}
+	if a.Stats().Sent != 1 {
+		t.Fatal("rejected batch changed counters")
+	}
+}
+
+func TestBatchBoundContextCloseCancelAndGeneration(t *testing.T) {
+	for _, owned := range []bool{false, true} {
+		for _, closeIt := range []bool{false, true} {
+			t.Run(map[bool]string{false: "borrowed", true: "owned"}[owned]+map[bool]string{false: "cancel", true: "close"}[closeIt], func(t *testing.T) {
+				a, b, _, _ := newBatchPair(t, owned, false)
+				ctx, cancel := context.WithCancel(context.Background())
+				defer cancel()
+				if err := b.BindLifetime(ctx); err != nil {
+					t.Fatal(err)
+				}
+				if err := b.BindLifetime(context.Background()); !errors.Is(err, ErrLifetimeBound) {
+					t.Fatalf("rebind %v", err)
+				}
+				if _, err := b.RecvBatch(context.Background(), receiveSlots(1, b.MaxMessageSize())); !errors.Is(err, ErrLifetimeContext) {
+					t.Fatalf("wrong context %v", err)
+				}
+				result := make(chan error, 1)
+				go func() { _, err := b.RecvBatch(ctx, receiveSlots(1, b.MaxMessageSize())); result <- err }()
+				select {
+				case e := <-result:
+					t.Fatalf("did not block %v", e)
+				case <-time.After(20 * time.Millisecond):
+				}
+				want := error(context.Canceled)
+				if closeIt {
+					want = ErrClosed
+					if err := b.Close(); err != nil {
+						t.Fatal(err)
+					}
+				} else {
+					cancel()
+				}
+				select {
+				case err := <-result:
+					if !errors.Is(err, want) {
+						t.Fatalf("got %v want %v", err, want)
+					}
+				case <-time.After(time.Second):
+					t.Fatal("IO did not unblock")
+				}
+				// A fresh generation is independent of the cancelled carrier.
+				c, d, _, _ := newBatchPair(t, owned, false)
+				fresh := bindPair(t, c, d)
+				if err := c.Send(fresh, []byte("new generation")); err != nil {
+					t.Fatal(err)
+				}
+				if msg, err := d.Recv(fresh); err != nil || string(msg) != "new generation" {
+					t.Fatalf("migration %q %v", msg, err)
+				}
+				_ = a
+			})
+		}
+	}
+}
+
+func TestBatchBorrowedCancellationDoesNotWakeOtherSocketUser(t *testing.T) {
+	_, b, ac, bc := newBatchPair(t, false, false)
+	ctx, cancel := context.WithCancel(context.Background())
+	if err := b.BindLifetime(ctx); err != nil {
+		t.Fatal(err)
+	}
+	result := make(chan error, 1)
+	if err := bc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
+		t.Fatal(err)
+	}
+	go func() {
+		buf := make([]byte, 64)
+		n, _, err := bc.ReadFromUDP(buf)
+		if err == nil && string(buf[:n]) != "other user" {
+			err = io.ErrUnexpectedEOF
+		}
+		result <- err
+	}()
+	cancel()
+	if err := b.Close(); err != nil {
+		t.Fatal(err)
+	}
+	select {
+	case e := <-result:
+		t.Fatalf("borrower changed shared read: %v", e)
+	case <-time.After(30 * time.Millisecond):
+	}
+	if _, err := ac.WriteToUDP([]byte("other user"), bc.LocalAddr().(*net.UDPAddr)); err != nil {
+		t.Fatal(err)
+	}
+	select {
+	case e := <-result:
+		if e != nil {
+			t.Fatal(e)
+		}
+	case <-time.After(time.Second):
+		t.Fatal("shared socket stopped")
+	}
+}
+
+func TestBatchPartialSendPrefixIsNeverReplayed(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, false)
+	ctx := bindPair(t, a, b)
+	s := &a.batch.tx
+	original := s.callback
+	calls := 0
+	s.callback = func(fd uintptr) bool {
+		calls++
+		count := s.count
+		s.count = 1
+		done := original(fd)
+		s.count = count
+		if s.n > 0 {
+			s.err = unix.ENOBUFS
+		}
+		return done
+	}
+	m := []BatchMsg{{Buffers: [][]byte{[]byte("first")}}, {Buffers: [][]byte{[]byte("second")}}, {Buffers: [][]byte{[]byte("third")}}}
+	n, err := a.SendBatch(ctx, m)
+	if n != 1 || !errors.Is(err, unix.ENOBUFS) || calls != 1 || m[0].N != 5 || m[1].N != 0 {
+		t.Fatalf("prefix %d err %v calls %d slots %+v", n, err, calls, m)
+	}
+	s.callback = original
+	sendAllBatch(t, a, ctx, m[n:])
+	recv := receiveSlots(3, b.MaxMessageSize())
+	got := 0
+	for got < 3 {
+		n, err = b.RecvBatch(ctx, recv[:3-got])
+		if err != nil {
+			t.Fatal(err)
+		}
+		for i := 0; i < n; i++ {
+			if string(flattenBatch(recv[i])) != string(m[got+i].Buffers[0]) {
+				t.Fatal("prefix repeated or order changed")
+			}
+		}
+		got += n
+	}
+	if a.Stats().Sent != 3 || a.Stats().SendErrors != 1 {
+		t.Fatalf("stats %+v", a.Stats())
+	}
+	for _, v := range a.batch.tx.iov {
+		if v.Base != nil {
+			t.Fatal("caller buffer retained after send")
+		}
+	}
+}
+
+func TestBatchBoundSteadyStateAllocs(t *testing.T) {
+	for _, owned := range []bool{false, true} {
+		t.Run(map[bool]string{false: "borrowed", true: "owned"}[owned], func(t *testing.T) {
+			a, b, _, _ := newBatchPair(t, owned, false)
+			ctx := bindPair(t, a, b)
+			send := []BatchMsg{{Buffers: [][]byte{make([]byte, 128)}}}
+			recv := receiveSlots(1, b.MaxMessageSize())
+			var runErr error
+			allocs := testing.AllocsPerRun(100, func() {
+				if _, e := a.SendBatch(ctx, send); e != nil {
+					runErr = e
+					return
+				}
+				if _, e := b.RecvBatch(ctx, recv); e != nil {
+					runErr = e
+				}
+			})
+			if runErr != nil {
+				t.Fatal(runErr)
+			}
+			if allocs != 0 {
+				t.Fatalf("bound datagram round trip allocated %g times", allocs)
+			}
+		})
+	}
+}
+
+func BenchmarkBatchBoundRoundTrip(b *testing.B) {
+	for _, count := range []int{1, 32} {
+		b.Run(map[int]string{1: "1", 32: "32"}[count], func(b *testing.B) {
+			a, c, _, _ := newBatchPair(b, true, false)
+			ctx := context.Background()
+			if err := a.BindLifetime(ctx); err != nil {
+				b.Fatal(err)
+			}
+			if err := c.BindLifetime(ctx); err != nil {
+				b.Fatal(err)
+			}
+			send := make([]BatchMsg, count)
+			for i := range send {
+				send[i].Buffers = [][]byte{make([]byte, 1024)}
+			}
+			recv := receiveSlots(count, c.MaxMessageSize())
+			b.ReportAllocs()
+			b.SetBytes(int64(1024 * count))
+			b.ResetTimer()
+			for i := 0; i < b.N; i++ {
+				for at := 0; at < count; {
+					n, e := a.SendBatch(ctx, send[at:])
+					if e != nil {
+						b.Fatal(e)
+					}
+					at += n
+				}
+				for at := 0; at < count; {
+					n, e := c.RecvBatch(ctx, recv[:count-at])
+					if e != nil {
+						b.Fatal(e)
+					}
+					at += n
+				}
+			}
+		})
+	}
+}
+
+func TestBatchNegotiatedSlotsBelowCarrierCeiling(t *testing.T) {
+	for _, offload := range []bool{false, true} {
+		t.Run(map[bool]string{false: "ordinary", true: "offload"}[offload], func(t *testing.T) {
+			a, b, _, _ := newBatchPair(t, true, offload)
+			ctx := bindPair(t, a, b)
+			m := []BatchMsg{{Buffers: [][]byte{make([]byte, 200)}}, {Buffers: [][]byte{make([]byte, 200)}}, {Buffers: [][]byte{[]byte("fits")}}}
+			sendAllBatch(t, a, ctx, m)
+			recv := receiveSlots(2, 100)
+			n, err := b.RecvBatch(ctx, recv)
+			if n != 1 || err != nil || string(flattenBatch(recv[0])) != "fits" {
+				t.Fatalf("negotiated receive %d %v", n, err)
+			}
+			if s := b.Stats(); s.Delivered != 1 || s.RecvErrors != 2 {
+				t.Fatalf("oversize delivery %+v", s)
+			}
+		})
+	}
+}
+
+func TestBatchDualStackAndIPv6(t *testing.T) {
+	for _, network := range []string{"udp", "udp6"} {
+		t.Run(network, func(t *testing.T) {
+			server, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv6unspecified})
+			if err != nil {
+				t.Skipf("IPv6 unavailable: %v", err)
+			}
+			defer server.Close()
+			clientNetwork, clientIP := "udp4", net.IPv4(127, 0, 0, 1)
+			if network == "udp6" {
+				clientNetwork, clientIP = "udp6", net.IPv6loopback
+			}
+			client, err := net.ListenUDP(clientNetwork, &net.UDPAddr{IP: clientIP})
+			if err != nil {
+				t.Fatal(err)
+			}
+			defer client.Close()
+			peer := client.LocalAddr().(*net.UDPAddr)
+			u, err := NewUDP(UDPConfig{Conn: server, Peer: peer, OwnsConn: true})
+			if err != nil {
+				t.Fatal(err)
+			}
+			defer u.Close()
+			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
+			defer cancel()
+			if err = u.BindLifetime(ctx); err != nil {
+				t.Fatal(err)
+			}
+			if err = u.Send(ctx, []byte("out")); err != nil {
+				t.Fatalf("mapped send: %v", err)
+			}
+			buf := make([]byte, 100)
+			client.SetReadDeadline(time.Now().Add(time.Second))
+			n, from, err := client.ReadFromUDP(buf)
+			if err != nil || string(buf[:n]) != "out" {
+				t.Fatalf("client recv %d %v", n, err)
+			}
+			if _, err = client.WriteToUDP([]byte("in"), from); err != nil {
+				t.Fatal(err)
+			}
+			recv := receiveSlots(1, u.MaxMessageSize())
+			n, err = u.RecvBatch(ctx, recv)
+			if err != nil || n != 1 || string(flattenBatch(recv[0])) != "in" {
+				t.Fatalf("mapped recv %d %v", n, err)
+			}
+			if !peerEqual(recv[0].Addr, peer.AddrPort()) {
+				t.Fatalf("peer %v source %v", peer, recv[0].Addr)
+			}
+		})
+	}
+}
+
+func TestBatchBindDuringIO(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, false)
+	ctx, cancel := context.WithCancel(context.Background())
+	defer cancel()
+	result := make(chan error, 1)
+	go func() { _, err := b.Recv(ctx); result <- err }()
+	deadline := time.Now().Add(time.Second)
+	for b.recvMu.TryLock() {
+		b.recvMu.Unlock()
+		if time.Now().After(deadline) {
+			t.Fatal("receive did not start")
+		}
+		runtime.Gosched()
+	}
+	if err := b.BindLifetime(context.Background()); !errors.Is(err, ErrConfig) {
+		t.Fatalf("bound over active IO: %v", err)
+	}
+	cancel()
+	select {
+	case <-result:
+	case <-time.After(time.Second):
+		t.Fatal("cancel did not finish")
+	}
+	fresh, cancelFresh := context.WithCancel(context.Background())
+	defer cancelFresh()
+	if err := b.BindLifetime(fresh); err != nil {
+		t.Fatalf("bind after unbound IO finished: %v", err)
+	}
+	if err := a.Send(context.Background(), []byte("okay")); err != nil {
+		t.Fatal(err)
+	}
+	if msg, err := b.Recv(fresh); err != nil || string(msg) != "okay" {
+		t.Fatalf("new lifetime %q %v", msg, err)
+	}
+}
+
+func TestBatchReadyDrainAndReceiveErrorPrefix(t *testing.T) {
+	a, b, _, _ := newBatchPair(t, true, false)
+	ctx := bindPair(t, a, b)
+	send := make([]BatchMsg, 4)
+	for i := range send {
+		send[i].Buffers = [][]byte{bytes.Repeat([]byte{byte(i + 1)}, 20)}
+	}
+	sendAllBatch(t, a, ctx, send)
+	recv := receiveSlots(32, b.MaxMessageSize())
+	n, err := b.RecvBatch(ctx, recv)
+	if n != 4 || err != nil {
+		t.Fatalf("ready drain should return four without waiting: %d %v", n, err)
+	}
+	for i := 0; i < n; i++ {
+		if !bytes.Equal(flattenBatch(recv[i]), send[i].Buffers[0]) {
+			t.Fatal("ready drain changed datagrams")
+		}
+	}
+	if err = a.Send(ctx, []byte("prefix")); err != nil {
+		t.Fatal(err)
+	}
+	s := &b.batch.rx
+	original := s.callback
+	s.callback = func(fd uintptr) bool {
+		done := original(fd)
+		if s.n > 0 {
+			s.err = unix.ENOBUFS
+		}
+		return done
+	}
+	n, err = b.RecvBatch(ctx, recv)
+	if n != 1 || !errors.Is(err, unix.ENOBUFS) || string(flattenBatch(recv[0])) != "prefix" {
+		t.Fatalf("receive prefix lost: %d %v", n, err)
+	}
+}
+
+func TestBatchMappedIPv4PeerOnIPv4Socket(t *testing.T) {
+	_, b, ac, bc := newBatchPair(t, true, false)
+	// net.IPv4 returns a 16-byte mapped address, including on an IPv4 socket.
+	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bc.LocalAddr().(*net.UDPAddr).Port}
+	a, err := NewUDP(UDPConfig{Conn: ac, Peer: peer})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer a.Close()
+	if !a.peer.AddrPort().Addr().Is4In6() {
+		t.Fatal("test requires mapped IPv4 input")
+	}
+	ctx := bindPair(t, a, b)
+	if err := a.Send(ctx, []byte("mapped IPv4")); err != nil {
+		t.Fatal(err)
+	}
+	if got, err := b.Recv(ctx); err != nil || string(got) != "mapped IPv4" {
+		t.Fatalf("%q %v", got, err)
+	}
+}
```

### winn_protocol_experimental/winn3/carrier/batch_unix.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/batch_unix.go
@@ -0,0 +1,711 @@
+//go:build linux || darwin
+
+package carrier
+
+import (
+	"context"
+	"io"
+	"net"
+	"net/netip"
+	"reflect"
+	"runtime"
+	"strconv"
+	"sync"
+	"syscall"
+	"time"
+	"unsafe"
+
+	"golang.org/x/sys/unix"
+)
+
+// mmsg matches Linux struct mmsghdr, including the trailing ABI alignment.
+// Darwin uses only Hdr and performs one recvmsg/sendmsg syscall per datagram,
+// draining immediately ready records without waiting to fill a batch.
+type mmsg struct {
+	Hdr unix.Msghdr
+	Len uint32
+}
+
+type batchIO struct {
+	hdr             [MaxBatchSize]mmsg
+	addr            [MaxBatchSize]unix.RawSockaddrAny
+	iov             [MaxBatchSize * MaxBatchBuffers]unix.Iovec
+	control         [MaxBatchSize][64]byte
+	groups          [MaxBatchSize]int
+	lengths         [MaxBatchSize]int
+	count           int
+	n               int
+	err             error
+	read            bool
+	noMmsg          bool
+	callback        func(uintptr) bool
+	controlCallback func(uintptr)
+	timer           *time.Timer
+}
+
+func (s *batchIO) init(read bool) {
+	s.read = read
+	s.callback = s.call
+	s.controlCallback = s.controlCall
+	s.timer = time.NewTimer(time.Hour)
+	s.timer.Stop()
+}
+
+func (s *batchIO) controlCall(fd uintptr) { s.call(fd) }
+
+func (s *batchIO) call(fd uintptr) bool {
+	for {
+		s.n, s.err = batchSyscall(fd, s)
+		if s.err == unix.EINTR && s.n == 0 {
+			continue
+		}
+		return s.err != unix.EAGAIN && s.err != unix.EWOULDBLOCK
+	}
+}
+
+type udpBatch struct {
+	configuredAddr    unix.RawSockaddrAny
+	configuredAddrLen int
+	pendingValid      [2]uint64
+	ipv6              bool
+	txPeer            netip.AddrPort
+	txAddr            unix.RawSockaddrAny
+	txAddrLen         int
+	raw               syscall.RawConn
+	sendMu            sync.Mutex
+	lifeMu            sync.Mutex
+	ctx               context.Context
+	stop              func() bool
+	finished          chan struct{}
+	done              chan struct{}
+	rx                batchIO
+	tx                batchIO
+	// Ordinary batches need only path-ceiling-sized staging. GRO uses exactly
+	// one 65535-byte staging buffer, with pending segments across small reads.
+	storage         []byte
+	stride          int
+	gro             bool
+	gso             bool
+	pendingN        int
+	pendingOffset   int
+	pendingSize     int
+	pendingSegments int
+	pendingAddr     netip.AddrPort
+	pendingFlags    int
+	oneRecv         [1]BatchMsg
+	oneRecvBuffers  [1][]byte
+	oneSend         [1]BatchMsg
+	oneSendBuffers  [1][]byte
+}
+
+func (u *UDP) initBatch(offload bool) error {
+	raw, err := u.conn.SyscallConn()
+	if err != nil {
+		return err
+	}
+	b := &udpBatch{raw: raw, done: make(chan struct{})}
+	b.ipv6 = u.conn.LocalAddr().(*net.UDPAddr).IP.To4() == nil
+	b.rx.init(true)
+	b.tx.init(false)
+	b.gro, b.gso = enableBatchOffload(raw, offload && u.owns)
+	b.stride = min(u.pathCeiling+1, maxRecvDatagram)
+	if b.stride < 1 {
+		b.stride = maxRecvDatagram
+	}
+	size := MaxBatchSize * b.stride
+	if b.gro {
+		b.stride, size = maxRecvDatagram, maxRecvDatagram
+	}
+	b.storage = make([]byte, size)
+	b.oneRecv[0].Buffers = b.oneRecvBuffers[:]
+	b.oneSend[0].Buffers = b.oneSendBuffers[:]
+	u.batch = b
+	return u.setBatchPeer(u.peer)
+}
+
+func (u *UDP) BindLifetime(ctx context.Context) error {
+	if ctx == nil || !reflect.TypeOf(ctx).Comparable() {
+		return ErrConfig
+	}
+	if err := ctx.Err(); err != nil {
+		return err
+	}
+	b := u.batch
+	if !b.sendMu.TryLock() {
+		return ErrConfig
+	}
+	defer b.sendMu.Unlock()
+	if !u.recvMu.TryLock() {
+		return ErrConfig
+	}
+	defer u.recvMu.Unlock()
+	b.lifeMu.Lock()
+	defer b.lifeMu.Unlock()
+	if b.ctx != nil {
+		return ErrLifetimeBound
+	}
+	u.mu.Lock()
+	defer u.mu.Unlock()
+	if u.closed {
+		return ErrClosed
+	}
+	// This is a setup operation. Callers must bind before launching IO; the
+	// state is protected even when Close races with that setup.
+	if u.owns {
+		deadline, _ := ctx.Deadline()
+		if err := u.conn.SetDeadline(deadline); err != nil {
+			return err
+		}
+		b.finished = make(chan struct{})
+		b.stop = context.AfterFunc(ctx, func() {
+			_ = u.conn.SetDeadline(aLongTimeAgo)
+			close(b.finished)
+		})
+	}
+	b.ctx = ctx
+	return nil
+}
+
+func (u *UDP) closeBatch() {
+	b := u.batch
+	if b == nil {
+		return
+	}
+	b.lifeMu.Lock()
+	defer b.lifeMu.Unlock()
+	close(b.done)
+	if b.stop != nil && !b.stop() {
+		<-b.finished
+	}
+}
+
+func (u *UDP) batchContext(ctx context.Context) (bool, error) {
+	if ctx == nil {
+		return false, ErrConfig
+	}
+	if err := ctx.Err(); err != nil {
+		return false, err
+	}
+	u.mu.Lock()
+	closed := u.closed
+	u.mu.Unlock()
+	if closed {
+		return false, ErrClosed
+	}
+	b := u.batch
+	b.lifeMu.Lock()
+	bound := b.ctx
+	b.lifeMu.Unlock()
+	if bound != nil && bound != ctx {
+		return false, ErrLifetimeContext
+	}
+	return bound != nil, nil
+}
+
+func (u *UDP) batchWait(ctx context.Context, s *batchIO) error {
+	b := u.batch
+	for {
+		if err := ctx.Err(); err != nil {
+			return err
+		}
+		select {
+		case <-b.done:
+			return ErrClosed
+		default:
+		}
+		var err error
+		if u.owns {
+			if s.read {
+				err = b.raw.Read(s.callback)
+			} else {
+				err = b.raw.Write(s.callback)
+			}
+		} else {
+			// Control guarantees descriptor lifetime but does not modify the
+			// shared poller's read/write deadlines or cancellation state.
+			err = b.raw.Control(s.controlCallback)
+		}
+		if err != nil {
+			if e := ctx.Err(); e != nil {
+				return e
+			}
+			select {
+			case <-b.done:
+				return ErrClosed
+			default:
+			}
+			return err
+		}
+		if s.err != unix.EAGAIN && s.err != unix.EWOULDBLOCK {
+			return s.err
+		}
+		// Shared descriptors cannot use deadlines to wake another user's IO.
+		// This reusable timer bounds local cancellation latency without any
+		// descriptor mutation or per-packet callback registration.
+		s.timer.Reset(time.Millisecond)
+		select {
+		case <-ctx.Done():
+			s.timer.Stop()
+			return ctx.Err()
+		case <-b.done:
+			s.timer.Stop()
+			return ErrClosed
+		case <-s.timer.C:
+		}
+	}
+}
+
+func (u *UDP) SendBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
+	b := u.batch
+	b.sendMu.Lock()
+	defer b.sendMu.Unlock()
+	return u.sendBatchLocked(ctx, msgs)
+}
+
+func (u *UDP) sendBatchLocked(ctx context.Context, msgs []BatchMsg) (int, error) {
+	bound, err := u.batchContext(ctx)
+	if err != nil {
+		return 0, err
+	}
+	if len(msgs) > MaxBatchSize {
+		return 0, ErrBatchSize
+	}
+	if len(msgs) == 0 {
+		return 0, nil
+	}
+	u.mu.Lock()
+	ceiling, peer := u.maxMessage, u.peer
+	if peer != nil {
+		u.batch.txPeer = peer.AddrPort()
+		u.batch.txAddr = u.batch.configuredAddr
+		u.batch.txAddrLen = u.batch.configuredAddrLen
+	}
+	u.mu.Unlock()
+	var ap netip.AddrPort
+	if peer != nil {
+		ap = peer.AddrPort()
+	} else {
+		ap = u.conn.RemoteAddr().(*net.UDPAddr).AddrPort()
+	}
+	b, s := u.batch, &u.batch.tx
+	for i := range msgs {
+		msgs[i].N = 0
+		n, e := batchBytes(msgs[i].Buffers)
+		if e != nil {
+			return 0, e
+		}
+		if n == 0 {
+			return 0, ErrMessageEmpty
+		}
+		if n > ceiling {
+			return 0, ErrMessageTooLarge
+		}
+		if msgs[i].Addr.IsValid() && !peerEqual(msgs[i].Addr, ap) {
+			return 0, ErrBatchPeer
+		}
+		s.lengths[i] = n
+	}
+	if u.owns && !bound {
+		stop := u.armWrite(ctx)
+		defer stop()
+	}
+	// Descriptors contain pointers into caller buffers only while this call
+	// holds sendMu. Clearing all iovecs on every exit prevents buffer retention.
+	defer clear(s.iov[:])
+	for {
+		if err = u.packSend(msgs, ap, peer != nil); err != nil {
+			return 0, err
+		}
+		err = u.batchWait(ctx, s)
+		if s.n == 0 && b.gso && offloadUnsupported(err) {
+			b.gso = false
+			continue
+		}
+		break
+	}
+	committed, bytes := 0, 0
+	for i := 0; i < s.n; i++ {
+		for j := 0; j < s.groups[i]; j++ {
+			msgs[committed].N = s.lengths[committed]
+			bytes += s.lengths[committed]
+			committed++
+		}
+	}
+	// sendmmsg may hide an error following its successful prefix. Never
+	// replay that prefix, and never count a suffix the kernel did not send.
+	if committed == 0 && err == nil {
+		err = io.ErrNoProgress
+	}
+	u.mu.Lock()
+	u.stats.Sent += uint64(committed)
+	u.stats.SentBytes += uint64(bytes)
+	if committed > 0 {
+		u.stats.LastSend = u.clock.Now()
+	}
+	if err != nil {
+		u.stats.SendErrors++
+	}
+	u.mu.Unlock()
+	runtime.KeepAlive(msgs)
+	return committed, err
+}
+
+func (u *UDP) packSend(msgs []BatchMsg, ap netip.AddrPort, explicit bool) error {
+	s := &u.batch.tx
+	if explicit && u.batch.txPeer != ap {
+		wireAP := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
+		if u.batch.ipv6 && wireAP.Addr().Is4() {
+			wireAP = netip.AddrPortFrom(netip.AddrFrom16(wireAP.Addr().As16()), ap.Port())
+		}
+		n, err := marshalBatchAddr(&u.batch.txAddr, wireAP)
+		if err != nil {
+			return err
+		}
+		u.batch.txAddrLen, u.batch.txPeer = n, ap
+	}
+	s.count, s.n, s.err = 0, 0, nil
+	vi := 0
+	for first := 0; first < len(msgs); {
+		last, size, total := first+1, s.lengths[first], s.lengths[first]
+		if u.batch.gso {
+			for last < len(msgs) && s.lengths[last] <= size && total+s.lengths[last] <= maxUDPAggregate {
+				n := s.lengths[last]
+				total += n
+				last++
+				if n < size {
+					break
+				}
+			}
+		}
+		i := s.count
+		h := &s.hdr[i]
+		*h = mmsg{}
+		start := vi
+		for j := first; j < last; j++ {
+			for _, buf := range msgs[j].Buffers {
+				if len(buf) == 0 {
+					continue
+				}
+				s.iov[vi].Base = &buf[0]
+				s.iov[vi].SetLen(len(buf))
+				vi++
+			}
+		}
+		h.Hdr.Iov = &s.iov[start]
+		h.Hdr.SetIovlen(vi - start)
+		if explicit {
+			s.addr[i] = u.batch.txAddr
+			n := u.batch.txAddrLen
+			h.Hdr.Name = (*byte)(unsafe.Pointer(&s.addr[i]))
+			h.Hdr.Namelen = uint32(n)
+		}
+		if last-first > 1 {
+			setSegmentControl(&h.Hdr, s.control[i][:], size)
+		}
+		s.groups[i] = last - first
+		s.count++
+		first = last
+	}
+	return nil
+}
+
+func (u *UDP) RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
+	u.recvMu.Lock()
+	defer u.recvMu.Unlock()
+	return u.recvBatchLocked(ctx, msgs)
+}
+
+func (u *UDP) recvBatchLocked(ctx context.Context, msgs []BatchMsg) (int, error) {
+	bound, err := u.batchContext(ctx)
+	if err != nil {
+		return 0, err
+	}
+	if len(msgs) > MaxBatchSize {
+		return 0, ErrBatchSize
+	}
+	if len(msgs) == 0 {
+		return 0, nil
+	}
+	u.mu.Lock()
+	ceiling := u.maxMessage
+	u.mu.Unlock()
+	for i := range msgs {
+		if len(msgs[i].Buffers) == 0 || len(msgs[i].Buffers) > MaxBatchBuffers {
+			return 0, ErrBatchSize
+		}
+		capacity := batchCapacity(msgs[i].Buffers)
+		if capacity == 0 {
+			return 0, io.ErrShortBuffer
+		}
+		msgs[i].N, msgs[i].Flags, msgs[i].SegmentSize, msgs[i].Segments = 0, 0, 0, 0
+		msgs[i].Addr = netip.AddrPort{}
+	}
+	if u.owns && !bound {
+		stop := u.armRead(ctx)
+		defer stop()
+	}
+	b, s := u.batch, &u.batch.rx
+	for {
+		if err := ctx.Err(); err != nil {
+			return 0, err
+		}
+		if b.pendingN > 0 {
+			if n := u.drainGRO(msgs, ceiling); n > 0 {
+				return n, nil
+			}
+			continue
+		}
+		s.count, s.n, s.err = len(msgs), 0, nil
+		if b.gro {
+			s.count = 1
+		}
+		for i := 0; i < s.count; i++ {
+			h := &s.hdr[i]
+			*h = mmsg{}
+			s.addr[i] = unix.RawSockaddrAny{}
+			s.iov[i].Base = &b.storage[i*b.stride]
+			s.iov[i].SetLen(b.stride)
+			h.Hdr.Iov = &s.iov[i]
+			h.Hdr.SetIovlen(1)
+			h.Hdr.Name = (*byte)(unsafe.Pointer(&s.addr[i]))
+			h.Hdr.Namelen = uint32(unsafe.Sizeof(s.addr[i]))
+			h.Hdr.Control = &s.control[i][0]
+			h.Hdr.SetControllen(len(s.control[i]))
+		}
+		err = u.batchWait(ctx, s)
+		if err != nil {
+			u.mu.Lock()
+			u.stats.RecvErrors++
+			u.mu.Unlock()
+			if s.n == 0 {
+				return 0, err
+			}
+		}
+		out := 0
+		for i := 0; i < s.n; i++ {
+			h := &s.hdr[i]
+			n, flags := int(h.Len), int(h.Hdr.Flags)
+			ap, ok := parseBatchAddr(&s.addr[i], h.Hdr.Namelen)
+			segment, controlOK := 0, false
+			if uint64(h.Hdr.Controllen) <= uint64(len(s.control[i])) {
+				segment, controlOK = parseSegmentControl(s.control[i][:int(h.Hdr.Controllen)])
+			}
+			parts := 1
+			if segment > 0 && n > 0 {
+				parts = (n + segment - 1) / segment
+			}
+			u.mu.Lock()
+			peer := u.peer
+			foreign := ok && peer != nil && !peerEqual(ap, peer.AddrPort())
+			if foreign {
+				u.stats.Foreign += uint64(parts)
+			}
+			u.mu.Unlock()
+			if foreign {
+				continue
+			}
+			if !ok || !controlOK || n == 0 || n > maxUDPAggregate || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || parts > maxGROSegments || (segment > 0 && !b.gro) {
+				u.mu.Lock()
+				u.stats.RecvErrors++
+				u.mu.Unlock()
+				continue
+			}
+			if segment > 0 {
+				b.pendingN, b.pendingOffset, b.pendingSize = n, 0, segment
+				b.pendingSegments, b.pendingAddr, b.pendingFlags = parts, ap, flags
+				// Delivery counters move when the kernel aggregate arrives,
+				// including valid segments queued for a smaller caller batch.
+				u.countGROArrival(ceiling, msgs)
+				out = u.drainGRO(msgs, ceiling)
+				continue
+			}
+			if n > ceiling || n > batchCapacity(msgs[out].Buffers) {
+				u.mu.Lock()
+				u.stats.RecvErrors++
+				u.mu.Unlock()
+				continue
+			}
+			putBatch(&msgs[out], b.storage[i*b.stride:i*b.stride+n], ap, flags, 0, 1)
+			out++
+			u.mu.Lock()
+			u.stats.Delivered++
+			u.stats.DeliveredBytes += uint64(n)
+			u.stats.LastDelivered = u.clock.Now()
+			u.mu.Unlock()
+		}
+		if out > 0 || err != nil {
+			return out, err
+		}
+	}
+}
+
+func (u *UDP) countGROArrival(ceiling int, msgs []BatchMsg) {
+	b := u.batch
+	u.mu.Lock()
+	defer u.mu.Unlock()
+	b.pendingValid = [2]uint64{}
+	accepted := 0
+	for at := 0; at < b.pendingN; at += b.pendingSize {
+		n := min(b.pendingSize, b.pendingN-at)
+		if n > ceiling || n > batchCapacity(msgs[accepted%len(msgs)].Buffers) {
+			u.stats.RecvErrors++
+			continue
+		}
+		index := at / b.pendingSize
+		b.pendingValid[index/64] |= uint64(1) << uint(index%64)
+		accepted++
+		u.stats.Delivered++
+		u.stats.DeliveredBytes += uint64(n)
+		u.stats.LastDelivered = u.clock.Now()
+	}
+}
+
+func (u *UDP) drainGRO(msgs []BatchMsg, ceiling int) int {
+	b := u.batch
+	u.mu.Lock()
+	if u.peer != nil && !peerEqual(b.pendingAddr, u.peer.AddrPort()) {
+		u.stats.Foreign += uint64((b.pendingN - b.pendingOffset + b.pendingSize - 1) / b.pendingSize)
+		b.pendingN = 0
+		u.mu.Unlock()
+		return 0
+	}
+	u.mu.Unlock()
+	out := 0
+	for b.pendingOffset < b.pendingN && out < len(msgs) {
+		at := b.pendingOffset
+		n := min(b.pendingSize, b.pendingN-at)
+		b.pendingOffset += n
+		index := at / b.pendingSize
+		if b.pendingValid[index/64]&(uint64(1)<<uint(index%64)) == 0 {
+			continue
+		}
+		if n > ceiling {
+			u.mu.Lock()
+			u.stats.RecvErrors++
+			u.mu.Unlock()
+			continue
+		}
+		if n > batchCapacity(msgs[out].Buffers) {
+			u.mu.Lock()
+			u.stats.RecvErrors++
+			u.mu.Unlock()
+			continue
+		}
+		putBatch(&msgs[out], b.storage[at:at+n], b.pendingAddr, b.pendingFlags, b.pendingSize, b.pendingSegments)
+		out++
+	}
+	if b.pendingOffset == b.pendingN {
+		b.pendingN = 0
+	}
+	return out
+}
+
+func (u *UDP) platformSend(ctx context.Context, msg []byte) (bool, error) {
+	b := u.batch
+	b.sendMu.Lock()
+	defer b.sendMu.Unlock()
+	b.oneSendBuffers[0] = msg
+	_, err := u.sendBatchLocked(ctx, b.oneSend[:])
+	b.oneSendBuffers[0] = nil
+	return true, err
+}
+
+func (u *UDP) platformRecv(ctx context.Context, dst []byte) (bool, []byte, error) {
+	u.recvMu.Lock()
+	defer u.recvMu.Unlock()
+	b := u.batch
+	buf := dst
+	if buf == nil {
+		buf = u.buf
+	}
+	b.oneRecvBuffers[0] = buf
+	_, err := u.recvBatchLocked(ctx, b.oneRecv[:])
+	b.oneRecvBuffers[0] = nil
+	if err != nil {
+		return true, nil, err
+	}
+	msg := buf[:b.oneRecv[0].N]
+	if dst == nil {
+		msg = append([]byte(nil), msg...)
+	}
+	return true, msg, nil
+}
+
+func marshalBatchAddr(dst *unix.RawSockaddrAny, ap netip.AddrPort) (int, error) {
+	*dst = unix.RawSockaddrAny{}
+	if !ap.IsValid() {
+		return 0, ErrBatchPeer
+	}
+	ip := ap.Addr()
+	if ip.Is4() {
+		a := (*unix.RawSockaddrInet4)(unsafe.Pointer(dst))
+		setBatchFamily4(a)
+		a.Addr = ip.As4()
+		p := (*[2]byte)(unsafe.Pointer(&a.Port))
+		p[0], p[1] = byte(ap.Port()>>8), byte(ap.Port())
+		return unix.SizeofSockaddrInet4, nil
+	}
+	a := (*unix.RawSockaddrInet6)(unsafe.Pointer(dst))
+	setBatchFamily6(a)
+	a.Addr = ip.As16()
+	p := (*[2]byte)(unsafe.Pointer(&a.Port))
+	p[0], p[1] = byte(ap.Port()>>8), byte(ap.Port())
+	if zone := ip.Zone(); zone != "" {
+		id, err := strconv.ParseUint(zone, 10, 32)
+		if err != nil {
+			iface, e := net.InterfaceByName(zone)
+			if e != nil {
+				return 0, e
+			}
+			id = uint64(iface.Index)
+		}
+		a.Scope_id = uint32(id)
+	}
+	return unix.SizeofSockaddrInet6, nil
+}
+
+func parseBatchAddr(src *unix.RawSockaddrAny, n uint32) (netip.AddrPort, bool) {
+	switch src.Addr.Family {
+	case unix.AF_INET:
+		if n < unix.SizeofSockaddrInet4 {
+			return netip.AddrPort{}, false
+		}
+		a := (*unix.RawSockaddrInet4)(unsafe.Pointer(src))
+		p := (*[2]byte)(unsafe.Pointer(&a.Port))
+		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(p[0])<<8|uint16(p[1])), true
+	case unix.AF_INET6:
+		if n < unix.SizeofSockaddrInet6 {
+			return netip.AddrPort{}, false
+		}
+		a := (*unix.RawSockaddrInet6)(unsafe.Pointer(src))
+		p := (*[2]byte)(unsafe.Pointer(&a.Port))
+		// Scope is local routing metadata. Peer filtering has historically
+		// compared unmapped IP and port, excluding scope. Sends retain the
+		// configured peer's zone; no per-packet interface lookup is needed.
+		return netip.AddrPortFrom(netip.AddrFrom16(a.Addr).Unmap(), uint16(p[0])<<8|uint16(p[1])), true
+	}
+	return netip.AddrPort{}, false
+}
+
+var _ BatchCarrier = (*UDP)(nil)
+var _ LifetimeBinder = (*UDP)(nil)
+
+// setBatchPeer resolves named zones on the setup/authenticated migration path.
+// The caller holds u.mu after construction; packet IO only copies this value.
+func (u *UDP) setBatchPeer(peer *net.UDPAddr) error {
+	if peer == nil {
+		return nil
+	}
+	ap := peer.AddrPort()
+	wireAP := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
+	if u.batch.ipv6 && wireAP.Addr().Is4() {
+		wireAP = netip.AddrPortFrom(netip.AddrFrom16(wireAP.Addr().As16()), ap.Port())
+	}
+	var addr unix.RawSockaddrAny
+	n, err := marshalBatchAddr(&addr, wireAP)
+	if err != nil {
+		return err
+	}
+	u.batch.configuredAddr, u.batch.configuredAddrLen = addr, n
+	return nil
+}
```

### winn_protocol_experimental/winn3/carrier/udp.go

<!-- winn345-patch:diff -->
```diff
--- a/winn_protocol_experimental/winn3/carrier/udp.go
+++ b/winn_protocol_experimental/winn3/carrier/udp.go
@@ -50,7 +50,8 @@
 // failover-suppression attack that costs one spoofed packet per second. Foreign
 // datagrams move Foreign and nothing else.
 type UDP struct {
-	conn *net.UDPConn
+	conn  *net.UDPConn
+	batch *udpBatch
 	// owns records whether Close should close the socket. A carrier handed a
 	// socket it did not open must not close it: on a gateway that socket serves
 	// every other session.
@@ -101,6 +102,11 @@
 	// OwnsConn tells Close whether it may close Conn. DialUDP always owns.
 	OwnsConn bool
 
+	// EnableUDPOffload opts owned Linux sockets into capability-probed UDP GRO
+	// and opportunistic GSO. Other platforms and borrowed sockets keep ordinary
+	// datagrams. Every segment remains a separately authenticated message.
+	EnableUDPOffload bool
+
 	// MaxMessageSize is the send ceiling. Zero means MaxMessageSizeFor at
 	// PathMTU for the resolved family. A caller whose session may migrate should
 	// pass Floor rather than either.
@@ -215,7 +221,7 @@
 	if err := applyConfiguredUDPSocketBuffers(&cfg); err != nil {
 		return nil, err
 	}
-	return &UDP{
+	u := &UDP{
 		conn:                  cfg.Conn,
 		peer:                  cfg.Peer,
 		explicit:              cfg.Peer != nil,
@@ -227,7 +233,16 @@
 		socketBufferRequested: cfg.socketBufferRequested,
 		socketBufferRead:      cfg.socketBufferRead,
 		socketBufferWrite:     cfg.socketBufferWrite,
-	}, nil
+	}
+	if cfg.Peer != nil {
+		cp := *cfg.Peer
+		cp.IP = append(net.IP(nil), cfg.Peer.IP...)
+		u.peer = &cp
+	}
+	if err := u.initBatch(cfg.EnableUDPOffload); err != nil {
+		return nil, err
+	}
+	return u, nil
 }
 
 // SocketBuffers reports the SO_RCVBUF/SO_SNDBUF this carrier asked for and
@@ -307,6 +322,9 @@
 		// the one counter the escalation policy trusts as mobility evidence.
 		return nil
 	}
+	if err := u.setBatchPeer(&cp); err != nil {
+		return err
+	}
 	u.peer = &cp
 	u.stats.PeerMoves++
 	u.stats.LastPeerMove = u.clock.Now()
@@ -362,6 +380,9 @@
 
 // Send writes one message as one datagram.
 func (u *UDP) Send(ctx context.Context, msg []byte) error {
+	if handled, err := u.platformSend(ctx, msg); handled {
+		return err
+	}
 	if err := ctx.Err(); err != nil {
 		return err
 	}
@@ -433,6 +454,9 @@
 }
 
 func (u *UDP) recvInto(ctx context.Context, dst []byte) ([]byte, error) {
+	if handled, msg, err := u.platformRecv(ctx, dst); handled {
+		return msg, err
+	}
 	if err := ctx.Err(); err != nil {
 		return nil, err
 	}
@@ -509,6 +533,7 @@
 	u.closed = true
 	owns := u.owns
 	u.mu.Unlock()
+	u.closeBatch()
 	if !owns {
 		// A gateway's socket serves every session on it. Closing a socket this
 		// carrier was merely lent would take down every other session as a side
```

### winn_protocol_experimental/winn3/core/batch.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/core/batch.go
@@ -0,0 +1,324 @@
+package core
+
+import (
+	"crypto/cipher"
+	"encoding/binary"
+	"errors"
+	"io"
+	"runtime"
+	"sync"
+)
+
+// MaxBatchSize bounds both outstanding crypto work and caller slot counts.
+const MaxBatchSize = 32
+
+var (
+	ErrBatchSize  = errors.New("winn3: batch exceeds 32 slots")
+	ErrPoolClosed = errors.New("winn3: crypto worker pool closed")
+)
+
+// CryptoPool is a bounded, reusable pool owned by one frame Driver. Calls are
+// serialized at the batch boundary, never by workers around individual AEADs.
+// Close joins workers; neither Close nor workers acquire session locks.
+type CryptoPool struct {
+	mu      sync.Mutex
+	queue   chan int
+	workers sync.WaitGroup
+	done    sync.WaitGroup
+	jobs    [MaxBatchSize]cryptoJob
+	count   int
+	closed  bool
+}
+
+type cryptoJob struct {
+	aead          cipher.AEAD
+	nonce         [AEADNonceSize]byte
+	dst, src, aad []byte
+	plain         []byte
+	err           error
+	open          bool
+}
+
+// NewCryptoPool starts at most min(GOMAXPROCS, 32) workers. A later reduction
+// in GOMAXPROCS is honored before the next batch by joining and resizing.
+func NewCryptoPool() *CryptoPool {
+	p := new(CryptoPool)
+	p.resizeLocked()
+	return p
+}
+
+func (p *CryptoPool) resizeLocked() {
+	n := min(runtime.GOMAXPROCS(0), MaxBatchSize)
+	if p.count == n {
+		return
+	}
+	if p.queue != nil {
+		close(p.queue)
+		p.workers.Wait()
+	}
+	p.queue = make(chan int, MaxBatchSize)
+	p.count = n
+	p.workers.Add(n)
+	for i := 0; i < n; i++ {
+		go p.worker()
+	}
+}
+
+func (p *CryptoPool) worker() {
+	defer p.workers.Done()
+	for i := range p.queue {
+		p.jobs[i].run()
+		p.done.Done()
+	}
+}
+
+func (j *cryptoJob) run() {
+	if j.open {
+		j.plain, j.err = j.aead.Open(j.dst[:0], j.nonce[:], j.src, j.aad)
+		if j.err != nil {
+			j.err = ErrDecrypt
+		}
+	} else {
+		j.aead.Seal(j.dst[:0], j.nonce[:], j.src, j.aad)
+	}
+	// Drop key references before reporting completion, including on failure.
+	j.aead = nil
+	clear(j.nonce[:])
+	j.dst, j.src, j.aad = nil, nil, nil
+}
+
+func (p *CryptoPool) runLocked(n int) {
+	p.done.Add(n)
+	for i := 0; i < n; i++ {
+		p.queue <- i
+	}
+	p.done.Wait()
+}
+
+// Close is idempotent and waits for the current bounded batch to finish.
+func (p *CryptoPool) Close() {
+	if p == nil {
+		return
+	}
+	p.mu.Lock()
+	defer p.mu.Unlock()
+	if p.closed {
+		return
+	}
+	p.closed = true
+	close(p.queue)
+	p.workers.Wait()
+	clear(p.jobs[:])
+	p.queue = nil
+	p.count = 0
+}
+
+// SealSlot describes one message. On success Dst contains the wire message.
+// All buffers must be disjoint across slots; Dst must not overlap Payload.
+type SealSlot struct {
+	Dst     []byte
+	Payload []byte
+	PadTo   int
+}
+
+// SealBatchInto reserves every nonce in slot order under sendMu, then runs raw
+// ChaCha20-Poly1305 in parallel. sendMu spans the join, so scalar sends, ratchets
+// and wipe cannot interleave. Validation failure consumes no nonce or bytes.
+func (s *Session) SealBatchInto(p *CryptoPool, slots []SealSlot) error {
+	if len(slots) > MaxBatchSize {
+		return ErrBatchSize
+	}
+	if len(slots) == 0 {
+		return nil
+	}
+	p.mu.Lock()
+	defer p.mu.Unlock()
+	if p.closed {
+		return ErrPoolClosed
+	}
+	p.resizeLocked()
+	s.sendMu.Lock()
+	defer s.sendMu.Unlock()
+	if s.wiped || s.sendAEAD == nil {
+		return ErrWiped
+	}
+	if s.sendCounter >= RejectAfterMessages || uint64(len(slots)) > RejectAfterMessages-s.sendCounter {
+		return ErrCounterExhausted
+	}
+	for i := range slots {
+		x := &slots[i]
+		if len(x.Payload) > MaxTransportPayload {
+			return ErrPayloadTooLarge
+		}
+		n := TransportOverhead() + len(x.Payload)
+		if x.PadTo != 0 && x.PadTo < n {
+			return ErrTargetLenTooSmall
+		}
+		if cap(x.Dst) < max(n, x.PadTo) {
+			return io.ErrShortBuffer
+		}
+	}
+	for i := range slots {
+		x := &slots[i]
+		x.Dst = x.Dst[:max(TransportOverhead()+len(x.Payload), x.PadTo)]
+		token := s.sendPRF.token(s.sendCounter)
+		copy(x.Dst, token[:])
+		plain := x.Dst[DemuxTokenSize : len(x.Dst)-AEADTagSize]
+		binary.BigEndian.PutUint16(plain, uint16(len(x.Payload)))
+		copy(plain[transportHeaderSize:], x.Payload)
+		clear(plain[transportHeaderSize+len(x.Payload):])
+		j := &p.jobs[i]
+		*j = cryptoJob{aead: s.sendAEAD, dst: plain, src: plain, aad: x.Dst[:DemuxTokenSize]}
+		copy(j.nonce[:], s.sendSalt[:])
+		binary.BigEndian.PutUint64(j.nonce[nonceSaltSize:], s.sendCounter)
+		s.sendCounter++
+		s.sentBytes += uint64(len(x.Dst))
+	}
+	p.runLocked(len(slots))
+	clear(p.jobs[:len(slots)])
+	return nil
+}
+
+// OpenSlot is an opaque speculative ticket plus caller-owned buffers. Msg must
+// remain unchanged until CommitOpen completes. Dst must not overlap ANY Msg or
+// another slot's Dst, even for duplicate messages. Plaintext is exposed only by
+// CommitOpen. A ticket can be committed once and contains no AEAD/key reference.
+type OpenSlot struct {
+	Msg, Dst []byte
+	owner    *Session
+	epoch    uint32
+	counter  uint64
+	plain    []byte
+	err      error
+	resolved bool
+	used     bool
+}
+
+// SpeculateOpenBatch performs ordered lookup, followed by parallel AEAD opens.
+// No token is reserved or consumed: a corrupt duplicate cannot starve a genuine
+// ticket. recvMu spans the worker join and all key references are dropped before
+// it is released. The owner must commit tickets in original input order.
+func (s *Session) SpeculateOpenBatch(p *CryptoPool, slots []OpenSlot) error {
+	if len(slots) > MaxBatchSize {
+		return ErrBatchSize
+	}
+	if len(slots) == 0 {
+		return nil
+	}
+	p.mu.Lock()
+	defer p.mu.Unlock()
+	if p.closed {
+		return ErrPoolClosed
+	}
+	p.resizeLocked()
+	s.recvMu.Lock()
+	defer s.recvMu.Unlock()
+	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
+		return ErrWiped
+	}
+	jobs := 0
+	var indices [MaxBatchSize]int
+	for i := range slots {
+		x := &slots[i]
+		*x = OpenSlot{Msg: x.Msg, Dst: x.Dst, owner: s, epoch: s.epoch}
+		if len(x.Msg) < TransportOverhead() {
+			x.err = ErrShortMessage
+			continue
+		}
+		if cap(x.Dst) < len(x.Msg)-DemuxTokenSize-AEADTagSize {
+			x.err = io.ErrShortBuffer
+			continue
+		}
+		x.counter, x.resolved = s.recvWindow.lookup(x.Msg[:DemuxTokenSize])
+		if !x.resolved {
+			x.err = ErrUnauthenticated
+			if !s.recvWindow.indexed() {
+				x.err = ErrCallerOwnsWindow
+			}
+			continue
+		}
+		j := &p.jobs[jobs]
+		*j = cryptoJob{aead: s.recvAEAD, dst: x.Dst, src: x.Msg[DemuxTokenSize:], aad: x.Msg[:DemuxTokenSize], open: true}
+		copy(j.nonce[:], s.recvSalt[:])
+		binary.BigEndian.PutUint64(j.nonce[nonceSaltSize:], x.counter)
+		indices[jobs] = i
+		jobs++
+	}
+	p.runLocked(jobs)
+	for i := 0; i < jobs; i++ {
+		x, j := &slots[indices[i]], &p.jobs[i]
+		x.plain, x.err = j.plain, j.err
+	}
+	clear(p.jobs[:jobs])
+	return nil
+}
+
+// PreviewOpen resolves an opaque ticket against the current epoch and window,
+// without consuming its token. It lets the frame owner identify a control
+// boundary before committing it. The returned view is still speculative and
+// must never be delivered before CommitOpen succeeds.
+func (s *Session) PreviewOpen(x *OpenSlot) ([]byte, error) {
+	s.recvMu.Lock()
+	defer s.recvMu.Unlock()
+	return s.resolveOpenLocked(x)
+}
+
+func (s *Session) resolveOpenLocked(x *OpenSlot) ([]byte, error) {
+	if x.used {
+		return nil, ErrUnauthenticated
+	}
+	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
+		return nil, ErrWiped
+	}
+	if len(x.Msg) < TransportOverhead() {
+		return nil, ErrShortMessage
+	}
+	if cap(x.Dst) < len(x.Msg)-DemuxTokenSize-AEADTagSize {
+		return nil, io.ErrShortBuffer
+	}
+	counter, ok := s.recvWindow.lookup(x.Msg[:DemuxTokenSize])
+	if !ok {
+		if !s.recvWindow.indexed() {
+			return nil, ErrCallerOwnsWindow
+		}
+		return nil, ErrUnauthenticated
+	}
+	if x.owner != s || x.epoch != s.epoch || !x.resolved || x.counter != counter {
+		copy(s.recvNonce[:], s.recvSalt[:])
+		binary.BigEndian.PutUint64(s.recvNonce[nonceSaltSize:], counter)
+		x.plain, x.err = s.recvAEAD.Open(x.Dst[:0], s.recvNonce[:], x.Msg[DemuxTokenSize:], x.Msg[:DemuxTokenSize])
+		if x.err != nil {
+			x.err = ErrDecrypt
+		}
+		x.owner, x.epoch, x.counter, x.resolved = s, s.epoch, counter, true
+	}
+	if x.err != nil {
+		return nil, x.err
+	}
+	plain := x.plain
+	if len(plain) < transportHeaderSize {
+		return nil, ErrDecrypt
+	}
+	n := int(binary.BigEndian.Uint16(plain))
+	if n > len(plain)-transportHeaderSize {
+		return nil, ErrDecrypt
+	}
+	return plain[transportHeaderSize : transportHeaderSize+n : transportHeaderSize+n], nil
+}
+
+// CommitOpen authenticates current ownership and replay eligibility, then
+// accounts bytes and consumes exactly one token. A new epoch or a token that
+// entered the window since speculation is retried with the current AEAD.
+func (s *Session) CommitOpen(x *OpenSlot) ([]byte, error) {
+	s.recvMu.Lock()
+	defer s.recvMu.Unlock()
+	plain, err := s.resolveOpenLocked(x)
+	x.used = true
+	x.owner, x.plain = nil, nil
+	if err != nil {
+		return nil, err
+	}
+	s.recvWindow.consumeKnown(x.counter, x.Msg[:DemuxTokenSize])
+	s.recvdBytes += uint64(len(x.Msg))
+	return plain, nil
+}
```

### winn_protocol_experimental/winn3/core/batch_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/core/batch_test.go
@@ -0,0 +1,467 @@
+package core
+
+import (
+	"bytes"
+	"crypto/cipher"
+	"encoding/binary"
+	"errors"
+	"fmt"
+	"io"
+	"runtime"
+	"sync"
+	"testing"
+	"time"
+)
+
+func batchPair(t testing.TB, window int) (*Session, *Session, *CryptoPool) {
+	t.Helper()
+	a, err := newSession(RoleInitiator, chain{}, window)
+	if err != nil {
+		t.Fatal(err)
+	}
+	z, err := newSession(RoleResponder, chain{}, window)
+	if err != nil {
+		t.Fatal(err)
+	}
+	p := NewCryptoPool()
+	t.Cleanup(func() { p.Close(); a.Wipe(); z.Wipe() })
+	return a, z, p
+}
+
+func batchInputs(msgs ...[]byte) []OpenSlot {
+	x := make([]OpenSlot, len(msgs))
+	for i, m := range msgs {
+		x[i] = OpenSlot{Msg: m, Dst: make([]byte, len(m))}
+	}
+	return x
+}
+
+type reorderedAEAD struct {
+	cipher.AEAD
+	second    chan struct{}
+	mu        sync.Mutex
+	completed []uint64
+}
+
+func (a *reorderedAEAD) Seal(dst, nonce, plain, aad []byte) []byte {
+	c := binary.BigEndian.Uint64(nonce[nonceSaltSize:])
+	if c == 0 {
+		<-a.second
+	}
+	out := a.AEAD.Seal(dst, nonce, plain, aad)
+	a.mu.Lock()
+	a.completed = append(a.completed, c)
+	a.mu.Unlock()
+	if c == 1 {
+		close(a.second)
+	}
+	return out
+}
+
+func (a *reorderedAEAD) Open(dst, nonce, msg, aad []byte) ([]byte, error) {
+	c := binary.BigEndian.Uint64(nonce[nonceSaltSize:])
+	if c == 0 {
+		<-a.second
+	}
+	out, err := a.AEAD.Open(dst, nonce, msg, aad)
+	a.mu.Lock()
+	a.completed = append(a.completed, c)
+	a.mu.Unlock()
+	if c == 1 {
+		close(a.second)
+	}
+	return out, err
+}
+
+func TestStage5BatchReceiveCompletionOrder(t *testing.T) {
+	old := runtime.GOMAXPROCS(2)
+	defer runtime.GOMAXPROCS(old)
+	a, z, p := batchPair(t, DefaultTokenWindow)
+	var x [MaxBatchSize]OpenSlot
+	for i := range x {
+		msg, err := a.Seal([]byte{byte(i)}, 0)
+		if err != nil {
+			t.Fatal(err)
+		}
+		x[i] = OpenSlot{Msg: msg, Dst: make([]byte, len(msg))}
+	}
+	wrapped := &reorderedAEAD{AEAD: z.recvAEAD, second: make(chan struct{})}
+	z.recvAEAD = wrapped
+	if err := z.SpeculateOpenBatch(p, x[:]); err != nil {
+		t.Fatal(err)
+	}
+	if wrapped.completed[0] == 0 {
+		t.Fatal("receive completion was not reordered")
+	}
+	for i := range x {
+		plain, err := z.CommitOpen(&x[i])
+		if err != nil || !bytes.Equal(plain, []byte{byte(i)}) {
+			t.Fatalf("receive ticket order %d: %v", i, err)
+		}
+	}
+}
+
+func TestStage5BatchAuthenticatedBadLengthKeepsToken(t *testing.T) {
+	a, z, p := batchPair(t, 8)
+	msg, err := a.Seal([]byte("real"), 100)
+	if err != nil {
+		t.Fatal(err)
+	}
+	bad := bytes.Clone(msg)
+	var nonce [AEADNonceSize]byte
+	copy(nonce[:], a.sendSalt[:])
+	body := make([]byte, len(msg)-DemuxTokenSize-AEADTagSize)
+	binary.BigEndian.PutUint16(body, 65535)
+	a.sendAEAD.Seal(bad[DemuxTokenSize:DemuxTokenSize], nonce[:], body, bad[:DemuxTokenSize])
+	x := batchInputs(bad, msg)
+	if err := z.SpeculateOpenBatch(p, x); err != nil {
+		t.Fatal(err)
+	}
+	if _, err := z.CommitOpen(&x[0]); err != ErrDecrypt {
+		t.Fatal("bad authenticated length accepted", err)
+	}
+	plain, err := z.CommitOpen(&x[1])
+	if err != nil || string(plain) != "real" {
+		t.Fatal("malformed duplicate consumed genuine token", err)
+	}
+	if z.RecvdBytes() != uint64(len(msg)) {
+		t.Fatal("malformed duplicate counted")
+	}
+}
+
+func TestStage5BatchNonceAndOrderedOutput(t *testing.T) {
+	old := runtime.GOMAXPROCS(2)
+	defer runtime.GOMAXPROCS(old)
+	a, z, p := batchPair(t, DefaultTokenWindow)
+	legacy, err := newSession(RoleInitiator, chain{}, DefaultTokenWindow)
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer legacy.Wipe()
+	wrapped := &reorderedAEAD{AEAD: a.sendAEAD, second: make(chan struct{})}
+	a.sendAEAD = wrapped
+	var slots [MaxBatchSize]SealSlot
+	for i := range slots {
+		slots[i] = SealSlot{Dst: make([]byte, 180), Payload: bytes.Repeat([]byte{byte(i)}, 80), PadTo: 160}
+	}
+	if err := a.SealBatchInto(p, slots[:]); err != nil {
+		t.Fatal(err)
+	}
+	if wrapped.completed[0] == 0 {
+		t.Fatal("test failed to force out-of-order completion")
+	}
+	seen := make(map[string]bool)
+	for i := range slots {
+		want, err := legacy.Seal(slots[i].Payload, slots[i].PadTo)
+		if err != nil || !bytes.Equal(want, slots[i].Dst) {
+			t.Fatalf("slot %d differs from sequential nonce order: %v", i, err)
+		}
+		token := string(slots[i].Dst[:DemuxTokenSize])
+		if seen[token] {
+			t.Fatal("nonce token reused")
+		}
+		seen[token] = true
+		got, err := z.Open(slots[i].Dst)
+		if err != nil || !bytes.Equal(got, slots[i].Payload) {
+			t.Fatalf("slot %d: %v", i, err)
+		}
+	}
+	if a.SendCounter() != MaxBatchSize || a.SentBytes() != MaxBatchSize*160 || z.RecvdBytes() != a.SentBytes() {
+		t.Fatal("unstable ordered byte accounting")
+	}
+	for i := range p.jobs {
+		if p.jobs[i].aead != nil || p.jobs[i].nonce != [AEADNonceSize]byte{} {
+			t.Fatal("worker retained an epoch reference")
+		}
+	}
+}
+
+func TestStage5BatchValidationAtomicAndCounterCeiling(t *testing.T) {
+	a, _, p := batchPair(t, 8)
+	x := []SealSlot{{Dst: make([]byte, 100), Payload: []byte("a")}, {Dst: make([]byte, 1), Payload: []byte("b")}}
+	if err := a.SealBatchInto(p, x); !errors.Is(err, io.ErrShortBuffer) {
+		t.Fatal(err)
+	}
+	if a.SendCounter() != 0 || a.SentBytes() != 0 {
+		t.Fatal("partial validation consumed nonce/bytes")
+	}
+	x[1].Dst = make([]byte, 100)
+	a.sendCounter = RejectAfterMessages - 1
+	if err := a.SealBatchInto(p, x); err != ErrCounterExhausted {
+		t.Fatal(err)
+	}
+	if a.sendCounter != RejectAfterMessages-1 || a.sentBytes != 0 {
+		t.Fatal("failed ceiling check reserved counters")
+	}
+	if err := a.SealBatchInto(p, x[:1]); err != nil {
+		t.Fatal(err)
+	}
+	if a.sendCounter != RejectAfterMessages {
+		t.Fatal("last permitted nonce not reserved")
+	}
+	if err := a.SealBatchInto(p, make([]SealSlot, 33)); err != ErrBatchSize {
+		t.Fatal(err)
+	}
+	p.Close()
+	if err := a.SealBatchInto(p, x[:1]); err != ErrPoolClosed {
+		t.Fatal(err)
+	}
+}
+
+func TestStage5PoolWorkerBoundsAndResize(t *testing.T) {
+	old := runtime.GOMAXPROCS(3)
+	defer runtime.GOMAXPROCS(old)
+	a, _, p := batchPair(t, 8)
+	if p.count != 3 {
+		t.Fatalf("worker count %d", p.count)
+	}
+	runtime.GOMAXPROCS(1)
+	x := []SealSlot{{Dst: make([]byte, 100), Payload: []byte("bounded")}}
+	if err := a.SealBatchInto(p, x); err != nil {
+		t.Fatal(err)
+	}
+	if p.count != 1 {
+		t.Fatalf("workers ignored GOMAXPROCS reduction: %d", p.count)
+	}
+	p.Close()
+	p.Close()
+	if p.count != 0 || p.queue != nil {
+		t.Fatal("closed workers retained")
+	}
+}
+
+func TestStage5BatchCorruptGenuineAndPendingDuplicate(t *testing.T) {
+	for _, corruptFirst := range []bool{true, false} {
+		t.Run(fmt.Sprint(corruptFirst), func(t *testing.T) {
+			a, z, p := batchPair(t, 8)
+			msg, err := a.Seal([]byte("authentic"), 100)
+			if err != nil {
+				t.Fatal(err)
+			}
+			bad := bytes.Clone(msg)
+			bad[len(bad)-1] ^= 1
+			x := batchInputs(msg, msg, bad)
+			if corruptFirst {
+				x = batchInputs(bad, msg, msg)
+			}
+			if err := z.SpeculateOpenBatch(p, x); err != nil {
+				t.Fatal(err)
+			}
+			if z.RecvdBytes() != 0 {
+				t.Fatal("speculation accounted bytes")
+			}
+			accepted := 0
+			for i := range x {
+				out, err := z.CommitOpen(&x[i])
+				if err == nil {
+					accepted++
+					if string(out) != "authentic" {
+						t.Fatal("corrupted plaintext")
+					}
+				}
+				if corruptFirst && i == 0 && err != ErrDecrypt {
+					t.Fatal("corrupt pending ticket did not fail AEAD", err)
+				}
+				if _, err := z.CommitOpen(&x[i]); err == nil {
+					t.Fatal("ticket committed twice")
+				}
+			}
+			if accepted != 1 || z.RecvdBytes() != uint64(len(msg)) {
+				t.Fatalf("accepted %d times, bytes %d", accepted, z.RecvdBytes())
+			}
+		})
+	}
+}
+
+func TestStage5BatchWindowRefillAndPreview(t *testing.T) {
+	a, z, p := batchPair(t, 8)
+	x := make([]OpenSlot, MaxBatchSize)
+	for i := range x {
+		msg, err := a.Seal([]byte{byte(i)}, 0)
+		if err != nil {
+			t.Fatal(err)
+		}
+		x[i] = OpenSlot{Msg: msg, Dst: make([]byte, len(msg))}
+	}
+	if err := z.SpeculateOpenBatch(p, x); err != nil {
+		t.Fatal(err)
+	}
+	if x[8].resolved {
+		t.Fatal("test did not exceed initial lookup window")
+	}
+	for i := range x {
+		before := z.RecvdBytes()
+		preview, err := z.PreviewOpen(&x[i])
+		if err != nil || !bytes.Equal(preview, []byte{byte(i)}) {
+			t.Fatalf("preview %d: %v", i, err)
+		}
+		if z.RecvdBytes() != before {
+			t.Fatal("preview consumed accounting")
+		}
+		plain, err := z.CommitOpen(&x[i])
+		if err != nil || !bytes.Equal(plain, preview) {
+			t.Fatalf("refilled slot %d: %v", i, err)
+		}
+	}
+	if z.RecvdBytes() != a.SentBytes() {
+		t.Fatal("refill accounting differs")
+	}
+}
+
+func TestStage5BatchEpochRetryAndWipeCancellation(t *testing.T) {
+	a, z, p := batchPair(t, 8)
+	old, _ := a.Seal([]byte("old"), 0)
+	late, _ := a.Seal([]byte("late old"), 0)
+	secret := bytes.Repeat([]byte{7}, 32)
+	if err := a.Rekey(secret); err != nil {
+		t.Fatal(err)
+	}
+	fresh, _ := a.Seal([]byte("new"), 0)
+	x := batchInputs(old, fresh, late)
+	if err := z.SpeculateOpenBatch(p, x); err != nil {
+		t.Fatal(err)
+	}
+	if _, err := z.CommitOpen(&x[0]); err != nil {
+		t.Fatal(err)
+	}
+	if err := z.Rekey(secret); err != nil {
+		t.Fatal(err)
+	}
+	out, err := z.CommitOpen(&x[1])
+	if err != nil || string(out) != "new" {
+		t.Fatal("speculative new-epoch failure was not retried", err)
+	}
+	if _, err := z.CommitOpen(&x[2]); err == nil {
+		t.Fatal("old epoch plaintext committed after cut")
+	}
+	fresh, _ = a.Seal([]byte("cancel"), 0)
+	x = batchInputs(fresh)
+	if err := z.SpeculateOpenBatch(p, x); err != nil {
+		t.Fatal(err)
+	}
+	before := z.RecvdBytes()
+	z.Wipe()
+	if _, err := z.CommitOpen(&x[0]); err != ErrWiped {
+		t.Fatal(err)
+	}
+	if z.RecvdBytes() != before || z.recvAEAD != nil || z.recvWindow != nil {
+		t.Fatal("canceled ticket changed wiped state")
+	}
+}
+
+type blockedBatchAEAD struct {
+	cipher.AEAD
+	entered chan struct{}
+	release chan struct{}
+	once    sync.Once
+}
+
+func (a *blockedBatchAEAD) pause() { a.once.Do(func() { close(a.entered); <-a.release }) }
+func (a *blockedBatchAEAD) Seal(dst, nonce, plain, aad []byte) []byte {
+	a.pause()
+	return a.AEAD.Seal(dst, nonce, plain, aad)
+}
+func (a *blockedBatchAEAD) Open(dst, nonce, msg, aad []byte) ([]byte, error) {
+	a.pause()
+	return a.AEAD.Open(dst, nonce, msg, aad)
+}
+
+func TestStage5BatchJoinBeforeRekeyWipeAndPoolClose(t *testing.T) {
+	for _, operation := range []string{"send-rekey", "recv-wipe", "pool-close"} {
+		t.Run(operation, func(t *testing.T) {
+			a, z, p := batchPair(t, 8)
+			block := &blockedBatchAEAD{entered: make(chan struct{}), release: make(chan struct{})}
+			workDone := make(chan error, 1)
+			if operation == "recv-wipe" {
+				msg, _ := a.Seal([]byte("pending"), 0)
+				block.AEAD = z.recvAEAD
+				z.recvAEAD = block
+				x := batchInputs(msg)
+				go func() { workDone <- z.SpeculateOpenBatch(p, x) }()
+			} else {
+				block.AEAD = a.sendAEAD
+				a.sendAEAD = block
+				x := []SealSlot{{Dst: make([]byte, 100), Payload: []byte("pending")}}
+				go func() { workDone <- a.SealBatchInto(p, x) }()
+			}
+			select {
+			case <-block.entered:
+			case <-time.After(3 * time.Second):
+				t.Fatal("worker did not start")
+			}
+			barrierDone := make(chan error, 1)
+			go func() {
+				switch operation {
+				case "send-rekey":
+					barrierDone <- a.Rekey(bytes.Repeat([]byte{9}, 32))
+				case "recv-wipe":
+					z.Wipe()
+					barrierDone <- nil
+				case "pool-close":
+					p.Close()
+					barrierDone <- nil
+				}
+			}()
+			select {
+			case err := <-barrierDone:
+				t.Fatalf("barrier passed live worker: %v", err)
+			case <-time.After(20 * time.Millisecond):
+			}
+			close(block.release)
+			select {
+			case err := <-workDone:
+				if err != nil {
+					t.Fatal(err)
+				}
+			case <-time.After(3 * time.Second):
+				t.Fatal("worker join deadlocked")
+			}
+			select {
+			case err := <-barrierDone:
+				if err != nil {
+					t.Fatal(err)
+				}
+			case <-time.After(3 * time.Second):
+				t.Fatal("barrier deadlocked")
+			}
+			for i := range p.jobs {
+				if p.jobs[i].aead != nil {
+					t.Fatal("old AEAD retained")
+				}
+			}
+		})
+	}
+}
+
+func BenchmarkStage5BatchRoundTrip(b *testing.B) {
+	for _, count := range []int{1, 8, 32} {
+		b.Run(fmt.Sprint(count), func(b *testing.B) {
+			a, z, p := batchPair(b, DefaultTokenWindow)
+			seal := make([]SealSlot, count)
+			open := make([]OpenSlot, count)
+			for i := range seal {
+				seal[i] = SealSlot{Dst: make([]byte, 1500), Payload: make([]byte, 1200)}
+				open[i].Dst = make([]byte, 1500)
+			}
+			b.ReportAllocs()
+			b.SetBytes(int64(count * 1200))
+			b.ResetTimer()
+			for i := 0; i < b.N; i++ {
+				if err := a.SealBatchInto(p, seal); err != nil {
+					b.Fatal(err)
+				}
+				for j := range open {
+					open[j].Msg = seal[j].Dst
+				}
+				if err := z.SpeculateOpenBatch(p, open); err != nil {
+					b.Fatal(err)
+				}
+				for j := range open {
+					if _, err := z.CommitOpen(&open[j]); err != nil {
+						b.Fatal(err)
+					}
+				}
+			}
+		})
+	}
+}
```

### winn_protocol_experimental/winn3/core/frame.go

<!-- winn345-patch:diff -->
```diff
--- a/winn_protocol_experimental/winn3/core/frame.go
+++ b/winn_protocol_experimental/winn3/core/frame.go
@@ -1,6 +1,9 @@
 package core
 
-import "encoding/binary"
+import (
+	"encoding/binary"
+	"io"
+)
 
 // Frames are the contents of a transport message's plaintext.
 //
@@ -106,7 +109,16 @@
 // would be a parsing differential between implementations, and a parsing
 // differential is a fingerprint.
 func ParseFrames(b []byte) ([]Frame, error) {
-	var out []Frame
+	return parseFrames(nil, b, true)
+}
+
+// ParseFramesInto decodes into caller-owned frame slots without allocating.
+// An insufficient frame capacity returns io.ErrShortBuffer, with no frames.
+func ParseFramesInto(dst []Frame, b []byte) ([]Frame, error) {
+	return parseFrames(dst[:0], b, false)
+}
+
+func parseFrames(out []Frame, b []byte, allocate bool) ([]Frame, error) {
 	for len(b) > 0 {
 		if len(b) < frameHeaderSize {
 			return nil, errWrap(ErrDecrypt, "trailing %d bytes are not a frame header", len(b))
@@ -119,7 +131,10 @@
 		if frameHeaderSize+n > len(b) {
 			return nil, errWrap(ErrDecrypt, "frame claims %d bytes but only %d remain", n, len(b)-frameHeaderSize)
 		}
-		out = append(out, Frame{Type: t, Value: b[frameHeaderSize : frameHeaderSize+n]})
+		if !allocate && len(out) == cap(out) {
+			return nil, io.ErrShortBuffer
+		}
+		out = append(out, Frame{Type: t, Value: b[frameHeaderSize : frameHeaderSize+n : frameHeaderSize+n]})
 		b = b[frameHeaderSize+n:]
 	}
 	return out, nil
```

### winn_protocol_experimental/winn3/driver/batch_loop.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/driver/batch_loop.go
@@ -0,0 +1,92 @@
+package driver
+
+import (
+	"context"
+
+	"winsvpn.local/winnprotocol/winn3/carrier"
+	"winsvpn.local/winnprotocol/winn3/session"
+)
+
+// drainBatch preserves the carrier generation for a whole ordered batch. A
+// partial syscall commits only its prefix. An error drops the remaining sealed
+// messages, just as scalar drain drops a failed message, without resealing or
+// retransmitting any committed nonce.
+func (l *Loop) drainBatch(ctx, cctx context.Context, c carrier.BatchCarrier) (int, error) {
+	moved := 0
+	for budget := 0; budget < maxDrainPerWake; {
+		limit := min(len(l.writeSlots), maxDrainPerWake-budget)
+		for i := 0; i < limit; i++ {
+			l.writeSlots[i] = l.writeStorage[i]
+		}
+		n, pollErr := l.sess.PollBatchInto(l.writeSlots[:limit])
+		l.syncGate()
+		for i := 0; i < n; i++ {
+			l.writeVectors[i][0] = l.writeSlots[i]
+			l.writeBatch[i].N = len(l.writeSlots[i])
+		}
+		if n == 0 {
+			return moved, pollErr
+		}
+		budget += n
+		for offset := 0; offset < n; {
+			sent, err := c.SendBatch(cctx, l.writeBatch[offset:n])
+			if sent < 0 || sent > n-offset || (sent == 0 && err == nil) {
+				l.c.sendFailed.Add(uint64(n - offset))
+				return moved, errWrap(ErrConfig, "carrier returned invalid send batch progress %d of %d", sent, n-offset)
+			}
+			l.c.messagesSent.Add(uint64(sent))
+			moved += sent
+			offset += sent
+			if err != nil {
+				l.c.sendFailed.Add(uint64(n - offset))
+				if ctx.Err() != nil {
+					return moved, ctx.Err()
+				}
+				return moved, pollErr
+			}
+		}
+		if pollErr != nil {
+			return moved, pollErr
+		}
+		if n < len(l.writeBatch) {
+			return moved, nil
+		}
+	}
+	l.signalWake()
+	return moved, nil
+}
+
+// deliverMessages respects the session's control boundaries. A control record
+// ends a prefix, so the physical gate is projected before any following DATA.
+// Packet views are consumed synchronously and wiped before scratch is reused.
+func (l *Loop) deliverMessages(slots []session.ReceiveSlot) bool {
+	defer func() {
+		for i := range slots {
+			clear(slots[i].Scratch)
+			clear(slots[i].Packets)
+			slots[i].Packets = slots[i].Packets[:0]
+			slots[i].Message = nil
+		}
+	}()
+	for offset := 0; offset < len(slots); {
+		n, err := l.sess.DeliverBatch(slots[offset:])
+		if n < 0 || n > len(slots)-offset || (n == 0 && err == nil) {
+			l.setCarrierErr(errWrap(ErrConfig, "session returned invalid receive batch progress %d", n))
+			l.signalWake()
+			return false
+		}
+		l.syncGate()
+		l.c.messagesReceived.Add(uint64(n))
+		for i := offset; i < offset+n; i++ {
+			for _, p := range slots[i].Packets {
+				l.deliverInner(p)
+			}
+		}
+		offset += n
+		l.signalWake()
+		if err != nil || l.sess.State().Terminal() {
+			return false
+		}
+	}
+	return true
+}
```

### winn_protocol_experimental/winn3/driver/batch_loop_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/driver/batch_loop_test.go
@@ -0,0 +1,163 @@
+package driver
+
+import (
+	"bytes"
+	"context"
+	"encoding/binary"
+	"io"
+	"sync"
+	"sync/atomic"
+	"testing"
+	"time"
+
+	"winsvpn.local/winnprotocol/winn3/carrier"
+	"winsvpn.local/winnprotocol/winn3/session"
+)
+
+// batchTestCarrier returns short successful send prefixes and coalesces only
+// already queued receive records. Its scalar methods deliberately fail: this
+// test must exercise the loop's batch path in both directions.
+type batchTestCarrier struct {
+	*carrier.Pipe
+	in      chan []byte
+	peer    *batchTestCarrier
+	done    chan struct{}
+	once    sync.Once
+	limit   int
+	largest atomic.Int64
+	hold    atomic.Bool
+	entered chan struct{}
+	release chan struct{}
+}
+
+func newBatchTestPair(t *testing.T) (*batchTestCarrier, *batchTestCarrier) {
+	t.Helper()
+	makeOne := func() *batchTestCarrier {
+		p, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP})
+		if err != nil {
+			t.Fatal(err)
+		}
+		return &batchTestCarrier{Pipe: p, in: make(chan []byte, 1024), done: make(chan struct{}), limit: 3, entered: make(chan struct{}, 1), release: make(chan struct{})}
+	}
+	a, b := makeOne(), makeOne()
+	a.peer, b.peer = b, a
+	return a, b
+}
+
+func (c *batchTestCarrier) Send(context.Context, []byte) error   { return io.ErrUnexpectedEOF }
+func (c *batchTestCarrier) Recv(context.Context) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
+func (c *batchTestCarrier) Close() error                         { c.once.Do(func() { close(c.done) }); return nil }
+func (c *batchTestCarrier) SendBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
+	for old := c.largest.Load(); int64(len(msgs)) > old && !c.largest.CompareAndSwap(old, int64(len(msgs))); old = c.largest.Load() {
+	}
+	if c.hold.Load() {
+		select {
+		case c.entered <- struct{}{}:
+		default:
+		}
+		select {
+		case <-c.release:
+		case <-ctx.Done():
+			return 0, ctx.Err()
+		}
+	}
+	n := min(len(msgs), c.limit)
+	for i := 0; i < n; i++ {
+		p := append([]byte(nil), msgs[i].Buffers[0]...)
+		select {
+		case c.peer.in <- p:
+		case <-ctx.Done():
+			return i, ctx.Err()
+		case <-c.done:
+			return i, carrier.ErrClosed
+		}
+	}
+	return n, nil
+}
+func (c *batchTestCarrier) RecvBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
+	put := func(i int, p []byte) error {
+		if len(p) > len(msgs[i].Buffers[0]) {
+			return io.ErrShortBuffer
+		}
+		msgs[i].N = copy(msgs[i].Buffers[0], p)
+		return nil
+	}
+	select {
+	case p := <-c.in:
+		if err := put(0, p); err != nil {
+			return 0, err
+		}
+	case <-ctx.Done():
+		return 0, ctx.Err()
+	case <-c.done:
+		return 0, carrier.ErrClosed
+	}
+	for i := 1; i < len(msgs); i++ {
+		select {
+		case p := <-c.in:
+			if err := put(i, p); err != nil {
+				return i, err
+			}
+		default:
+			return i, nil
+		}
+	}
+	return len(msgs), nil
+}
+
+func TestBatchLoopPartialPrefixesPreservePacketOrder(t *testing.T) {
+	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
+	defer cancel()
+	a, b := newBatchTestPair(t)
+	defer a.Close()
+	defer b.Close()
+	kr := newKeyring(t)
+	sz := planSizing(t)
+	cli := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: a, local: clientAddr(), router: gatewayAddr(), tweak: quietBackpressure})
+	gw := newGatewayEndpoint(t, kr, endpointOpts{sizing: sz, carrier: b, local: gatewayAddr(), router: clientAddr(), tweak: quietBackpressure})
+	defer cli.stop()
+	defer gw.stop()
+	cli.start(ctx)
+	gw.start(ctx)
+	cli.waitState(session.StateEstablished, 5*time.Second)
+	gw.waitState(session.StateEstablished, 5*time.Second)
+	waitFor(t, 5*time.Second, "both batch gates", func() bool { return cli.loop.Carrying() && gw.loop.Carrying() })
+	a.hold.Store(true)
+	packet := func(i uint32) []byte {
+		p := make([]byte, sz.InnerMTU-20)
+		binary.BigEndian.PutUint32(p, i)
+		return ipv4Packet(clientAddr(), gatewayAddr(), p)
+	}
+	if err := cli.loop.SendInner(packet(0)); err != nil {
+		t.Fatal(err)
+	}
+	select {
+	case <-a.entered:
+	case <-ctx.Done():
+		t.Fatal("send did not reach batch carrier")
+	}
+	for i := 1; i <= 64; i++ {
+		if err := cli.loop.SendInner(packet(uint32(i))); err != nil {
+			t.Fatal(err)
+		}
+	}
+	a.hold.Store(false)
+	close(a.release)
+	for i := 0; i <= 64; i++ {
+		got := gw.dev.take(t, 5*time.Second)
+		if !bytes.Equal(got, packet(uint32(i))) {
+			t.Fatalf("packet %d corrupted, duplicated, or reordered", i)
+		}
+	}
+	if a.largest.Load() < 2 {
+		t.Fatalf("never sent a multi-record batch: %d", a.largest.Load())
+	}
+	select {
+	case <-gw.dev.out:
+		t.Fatal("duplicate packet after completed send prefixes")
+	default:
+	}
+	cancel()
+	_ = cli.waitRun(5 * time.Second)
+	_ = gw.waitRun(5 * time.Second)
+}
```

### winn_protocol_experimental/winn3/driver/loop.go

<!-- winn345-patch:json -->
```json
[
  "--- a/winn_protocol_experimental/winn3/driver/loop.go\n",
  "+++ b/winn_protocol_experimental/winn3/driver/loop.go\n",
  "@@ -133,7 +133,12 @@\n",
  " \n",
  " \tcloseOnce sync.Once\n",
  " \n",
  "-\twriteBuf []byte\n",
  "+\twriteBuf     []byte\n",
  "+\twriteBatch   [carrier.MaxBatchSize]carrier.BatchMsg\n",
  "+\twriteVectors [carrier.MaxBatchSize][1][]byte\n",
  "+\twriteStorage [carrier.MaxBatchSize][]byte\n",
  "+\twriteSlots   [carrier.MaxBatchSize][]byte\n",
  "+\tmigrateMu    sync.Mutex\n",
  " \n",
  " \tc counters\n",
  " }\n",
  "@@ -217,6 +222,11 @@\n",
  " \t\tcar:      cfg.Carrier,\n",
  " \t\topenedAt: cfg.Clock.Now(),\n",
  " \t\twriteBuf: make([]byte, 65536),\n",
  "+\t}\n",
  "+\tfor i := range l.writeBatch {\n",
  "+\t\tl.writeStorage[i] = make([]byte, cfg.Sizing.MessageSize)\n",
  "+\t\tl.writeVectors[i][0] = l.writeStorage[i]\n",
  "+\t\tl.writeBatch[i].Buffers = l.writeVectors[i][:]\n",
  " \t}\n",
  " \n",
  " \tif cfg.Tun != nil {\n",
  "@@ -423,10 +433,22 @@\n",
  " \tctx, cancel := context.WithCancel(ctx)\n",
  " \tdefer cancel()\n",
  " \n",
  "+\tl.migrateMu.Lock()\n",
  " \tl.mu.Lock()\n",
  " \tl.base = ctx\n",
  " \tl.carCtx, l.carStop = context.WithCancel(ctx)\n",
  "+\tif binder, ok := l.car.(carrier.LifetimeBinder); ok {\n",
  "+\t\tif err := binder.BindLifetime(l.carCtx); err != nil {\n",
  "+\t\t\tl.carStop()\n",
  "+\t\t\tl.mu.Unlock()\n",
  "+\t\t\tl.migrateMu.Unlock()\n",
  "+\t\t\tl.latchDown()\n",
  "+\t\t\tl.finished.Store(true)\n",
  "+\t\t\treturn err\n",
  "+\t\t}\n",
  "+\t}\n",
  " \tl.mu.Unlock()\n",
  "+\tl.migrateMu.Unlock()\n",
  " \n",
  " \tvar wg sync.WaitGroup\n",
  " \tif l.tn != nil {\n",
  "@@ -454,6 +476,7 @@\n",
  " \tcancel()\n",
  " \tl.stopCarrier()\n",
  " \twg.Wait()\n",
  "+\tl.sess.StopCryptoWorkers()\n",
  " \treturn err\n",
  " }\n",
  " \n",
  "@@ -532,6 +555,11 @@\n",
  " // one. The message is counted as lost and the loop waits rather than spinning on\n",
  " // a carrier that is refusing.\n",
  " func (l *Loop) drain(ctx context.Context) (int, error) {\n",
  "+\tif c, cctx, _ := l.currentCarrier(); c != nil {\n",
  "+\t\tif batch, ok := c.(carrier.BatchCarrier); ok {\n",
  "+\t\t\treturn l.drainBatch(ctx, cctx, batch)\n",
  "+\t\t}\n",
  "+\t}\n",
  " \tmoved := 0\n",
  " \tfor i := 0; i < maxDrainPerWake; i++ {\n",
  " \t\tmsg, err := l.sess.PollInto(l.writeBuf)\n",
  "@@ -595,6 +623,15 @@\n",
  " // packets that come back out into the tun layer.\n",
  " func (l *Loop) readLoop(ctx context.Context) {\n",
  " \tscratch := make([]byte, 65535)\n",
  "+\tvar msgs [carrier.MaxBatchSize]carrier.BatchMsg\n",
  "+\tvar vectors [carrier.MaxBatchSize][1][]byte\n",
  "+\tvar slots [carrier.MaxBatchSize]session.ReceiveSlot\n",
  "+\tfor i := range msgs {\n",
  "+\t\tvectors[i][0] = make([]byte, l.sizing.MessageSize)\n",
  "+\t\tmsgs[i].Buffers = vectors[i][:]\n",
  "+\t\tslots[i].Scratch = make([]byte, l.sizing.MessageSize)\n",
  "+\t\tslots[i].Packets = make([][]byte, 0, l.sizing.MessageSize/3)\n",
  "+\t}\n",
  " \ttype receiverInto interface {\n",
  " \t\tRecvInto(context.Context, []byte) ([]byte, error)\n",
  " \t}\n",
  "@@ -603,10 +640,35 @@\n",
  " \t\tc, cctx, gen := l.currentCarrier()\n",
  " \t\tvar msg []byte\n",
  " \t\tvar err error\n",
  "-\t\tif into, ok := c.(receiverInto); ok {\n",
  "+\t\tn := 0\n",
  "+\t\tif batch, ok := c.(carrier.BatchCarrier); ok {\n",
  "+\t\t\tn, err = batch.RecvBatch(cctx, msgs[:])\n",
  "+\t\t\tif n < 0 || n > len(msgs) {\n",
  "+\t\t\t\terr = errWrap(ErrConfig, \"carrier returned invalid receive batch count %d\", n)\n",
  "+\t\t\t\tn = 0\n",
  "+\t\t\t}\n",
  "+\t\t} else if into, ok := c.(receiverInto); ok {\n",
  " \t\t\tmsg, err = into.RecvInto(cctx, scratch)\n",
  " \t\t} else {\n",
  " \t\t\tmsg, err = c.Recv(cctx)\n",
  "+\t\t}\n",
  "+\t\tif l.carrierGeneration() != gen {\n",
  "+\t\t\tconsecutive = 0\n",
  "+\t\t\tcontinue\n",
  "+\t\t}\n",
  "+\t\t// A batched receive can return a valid prefix and a terminal error.\n",
  "+\t\t// Consume the prefix once before handling that error.\n",
  "+\t\tvalid := 0\n",
  "+\t\tfor i := 0; i < n; i++ {\n",
  "+\t\t\tif msgs[i].N <= 0 || msgs[i].N > len(msgs[i].Buffers[0]) {\n",
  "+\t\t\t\tl.c.recvFailed.Add(1)\n",
  "+\t\t\t\tcontinue\n",
  "+\t\t\t}\n",
  "+\t\t\tslots[valid].Message = msgs[i].Buffers[0][:msgs[i].N]\n",
  "+\t\t\tvalid++\n",
  "+\t\t}\n",
  "+\t\tif valid > 0 && !l.deliverMessages(slots[:valid]) {\n",
  "+\t\t\treturn\n",
  " \t\t}\n",
  " \t\tif err != nil {\n",
  " \t\t\tif ctx.Err() != nil {\n",
  "@@ -635,39 +697,54 @@\n",
  " \t\t\tcontinue\n",
  " \t\t}\n",
  " \t\tconsecutive = 0\n",
  "-\n",
  "-\t\tinner, err := l.sess.Deliver(msg)\n",
  "-\t\tif err != nil {\n",
  "-\t\t\t// Terminal. The write loop observes the same state and returns.\n",
  "+\t\tif n > 0 {\n",
  "+\t\t\tcontinue\n",
  "+\t\t}\n",
  "+\t\tif msg == nil {\n",
  "+\t\t\tl.setCarrierErr(errWrap(ErrConfig, \"carrier returned an empty receive batch without error\"))\n",
  " \t\t\tl.signalWake()\n",
  " \t\t\treturn\n",
  " \t\t}\n",
  "-\t\t// Apply the state this Deliver may just have reached, HERE, on the\n",
  "-\t\t// goroutine that reached it.\n",
  "-\t\t//\n",
  "-\t\t// The gate used to open one wake later, because only the write loop\n",
  "-\t\t// synced it: the message that completes the handshake is opened on this\n",
  "-\t\t// goroutine, and the gate did not open until the writer's next pass. The\n",
  "-\t\t// asymmetry was recorded as deliberate and harmless \u2014 closing is latched,\n",
  "-\t\t// opening may be late \u2014 and its cost was then measured: a host that\n",
  "-\t\t// starts writing the instant Session().State() reads \"established\" loses\n",
  "-\t\t// the whole burst, 64 of 64 packets to TxDroppedClosed, under -race.\n",
  "-\t\t//\n",
  "-\t\t// This is not a second writer of the gate in the sense that matters.\n",
  "-\t\t// syncGate takes gateMu and returns immediately once l.down is set, and\n",
  "-\t\t// l.down is monotone, so the CLOSING direction still cannot lose a race\n",
  "-\t\t// however many goroutines call it: whichever caller latches down first\n",
  "-\t\t// makes every later call a no-op. Only the opening direction moves, and\n",
  "-\t\t// only forward.\n",
  "-\t\tl.syncGate()\n",
  "-\t\tl.c.messagesReceived.Add(1)\n",
  "-\t\tfor _, p := range inner {\n",
  "-\t\t\tl.deliverInner(p)\n",
  "-\t\t}\n",
  "-\t\t// A delivered message may have changed the state, answered a probe, or\n",
  "-\t\t// left something queued. Poll is the only thing that can tell.\n",
  "+\t\tif !l.deliverMessage(msg) {\n",
  "+\t\t\treturn\n",
  "+\t\t}\n",
  "+\t}\n",
  "+}\n",
  "+\n",
  "+// deliverMessage projects each control transition before writing inner packets.\n",
  "+func (l *Loop) deliverMessage(msg []byte) bool {\n",
  "+\tinner, err := l.sess.Deliver(msg)\n",
  "+\tif err != nil {\n",
  "+\t\t// Terminal. The write loop observes the same state and returns.\n",
  " \t\tl.signalWake()\n",
  "-\t}\n",
  "+\t\treturn false\n",
  "+\t}\n",
  "+\t// Apply the state this Deliver may just have reached, HERE, on the\n",
  "+\t// goroutine that reached it.\n",
  "+\t//\n",
  "+\t// The gate used to open one wake later, because only the write loop\n",
  "+\t// synced it: the message that completes the handshake is opened on this\n",
  "+\t// goroutine, and the gate did not open until the writer's next pass. The\n",
  "+\t// asymmetry was recorded as deliberate and harmless \u2014 closing is latched,\n",
  "+\t// opening may be late \u2014 and its cost was then measured: a host that\n",
  "+\t// starts writing the instant Session().State() reads \"established\" loses\n",
  "+\t// the whole burst, 64 of 64 packets to TxDroppedClosed, under -race.\n",
  "+\t//\n",
  "+\t// This is not a second writer of the gate in the sense that matters.\n",
  "+\t// syncGate takes gateMu and returns immediately once l.down is set, and\n",
  "+\t// l.down is monotone, so the CLOSING direction still cannot lose a race\n",
  "+\t// however many goroutines call it: whichever caller latches down first\n",
  "+\t// makes every later call a no-op. Only the opening direction moves, and\n",
  "+\t// only forward.\n",
  "+\tl.syncGate()\n",
  "+\tl.c.messagesReceived.Add(1)\n",
  "+\tfor _, p := range inner {\n",
  "+\t\tl.deliverInner(p)\n",
  "+\t}\n",
  "+\t// A delivered message may have changed the state, answered a probe, or\n",
  "+\t// left something queued. Poll is the only thing that can tell.\n",
  "+\tl.signalWake()\n",
  "+\treturn true\n",
  " }\n",
  " \n",
  " // maxRecvErrors is how many consecutive carrier read errors are tolerated\n",
  "@@ -877,6 +954,8 @@\n",
  " // It does NOT close the old carrier. Closing is the caller's, because a caller\n",
  " // may want to hold a UDP socket open while it probes the replacement.\n",
  " func (l *Loop) Migrate(to carrier.Conn) (carrier.Migration, error) {\n",
  "+\tl.migrateMu.Lock()\n",
  "+\tdefer l.migrateMu.Unlock()\n",
  " \tif to == nil {\n",
  " \t\treturn carrier.Migration{}, errWrap(ErrConfig, \"no destination carrier\")\n",
  " \t}\n",
  "@@ -895,22 +974,36 @@\n",
  " \t// compile rather than migrating with a nil sink. A nil sink on a narrowing\n",
  " \t// move is a loud refusal (ErrMigrationWouldBlackHole), not a black hole;\n",
  " \t// the compile pin is so that loud path cannot be lost by accident.\n",
  "+\tl.mu.Lock()\n",
  "+\tbase := l.base\n",
  "+\tstarted := base != nil\n",
  "+\tif base == nil {\n",
  "+\t\tbase = context.Background()\n",
  "+\t}\n",
  "+\tl.mu.Unlock()\n",
  "+\tnextCtx, nextStop := context.WithCancel(base)\n",
  "+\tif started {\n",
  "+\t\tif binder, ok := to.(carrier.LifetimeBinder); ok {\n",
  "+\t\t\tif err := binder.BindLifetime(nextCtx); err != nil {\n",
  "+\t\t\t\tnextStop()\n",
  "+\t\t\t\treturn carrier.Migration{}, err\n",
  "+\t\t\t}\n",
  "+\t\t}\n",
  "+\t}\n",
  "+\t// A lifetime refusal must precede any session-size mutation. A destination\n",
  "+\t// whose migration fails after binding is retired and must be replaced.\n",
  " \tm, err := carrier.Migrate(l.sess, from, to, l.sizing.MessageSize)\n",
  " \tif err != nil {\n",
  "+\t\tnextStop()\n",
  " \t\treturn m, err\n",
  " \t}\n",
  "-\n",
  " \tl.mu.Lock()\n",
  " \told := l.carStop\n",
  "-\tbase := l.base\n",
  "-\tif base == nil {\n",
  "-\t\tbase = context.Background()\n",
  "-\t}\n",
  " \tl.car = to\n",
  " \tl.carGen++\n",
  " \tl.openedAt = l.clock.Now()\n",
  " \tl.carErr = nil\n",
  "-\tl.carCtx, l.carStop = context.WithCancel(base)\n",
  "+\tl.carCtx, l.carStop = nextCtx, nextStop\n",
  " \tl.mu.Unlock()\n",
  " \n",
  " \t// Unblock the reader's Recv on the old carrier. It observes the generation\n"
]
```

### winn_protocol_experimental/winn3/hostqueue/carrier.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/hostqueue/carrier.go
@@ -0,0 +1,207 @@
+// SPDX-License-Identifier: MIT
+// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
+// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
+package hostqueue
+
+import (
+	"bytes"
+	"context"
+	"crypto/tls"
+	"fmt"
+	"net"
+	"os"
+	"time"
+	"winsvpn.local/winnprotocol/internal/echconfig"
+	"winsvpn.local/winnprotocol/internal/tlsconfig"
+	"winsvpn.local/winnprotocol/winn3/carrier"
+	"winsvpn.local/winnprotocol/winn3/core"
+	"winsvpn.local/winnprotocol/winn3/driver"
+	"winsvpn.local/winnprotocol/winn3/session"
+)
+
+const winn3DialTimeout = 30 * time.Second
+
+func winn3BuildSession(
+	profile winn3Profile,
+) (session.Config, []byte, error) {
+	staticKeyBytes, err := ReadKeyFile(profile.Keys.StaticPath, "keys.static_path")
+	if err != nil {
+		return session.Config{}, nil, err
+	}
+	staticKey, err := core.NewStaticKey(staticKeyBytes)
+	if err != nil {
+		return session.Config{}, nil, fmt.Errorf("keys.static_path: %w", err)
+	}
+	admission, err := ReadPrivateKeyFile(profile.Keys.AdmissionPath, "keys.admission_path")
+	if err != nil {
+		return session.Config{}, nil, err
+	}
+	admission = bytes.TrimRight(admission, "\r\n")
+
+	cfg := session.Config{
+		Core: core.Config{
+			Gateway: core.GatewayParams{
+				AdmissionKeys: [][]byte{admission},
+				GatewayID:     []byte(profile.GatewayID),
+			},
+		},
+		Static:  staticKey,
+		Padding: core.PadBucket,
+		FastPQ:  profile.FastPQ,
+	}
+	switch profile.Role {
+	case winn3RoleClient:
+		gatewayBytes, err := ReadKeyFile(
+			profile.Keys.GatewayStaticPath, "keys.gateway_static_path")
+		if err != nil {
+			return session.Config{}, nil, err
+		}
+		gatewayStatic, err := core.NewPublicKey(gatewayBytes)
+		if err != nil {
+			return session.Config{}, nil, fmt.Errorf(
+				"keys.gateway_static_path: %w", err)
+		}
+		cfg.GatewayStatic = gatewayStatic
+		if err := ApplyDualAuthPublics(
+			&cfg, profile.Keys.DualAuthEd25519PubPath, profile.Keys.DualAuthMLDSA65PubPath,
+		); err != nil {
+			return session.Config{}, nil, err
+		}
+	case winn3RoleGateway:
+		cfg.Accept = func([]byte) error { return nil }
+	}
+	return cfg, admission, nil
+}
+
+func winn3DialCarrier(
+	ctx context.Context,
+	profile winn3Profile,
+	sizing driver.Sizing,
+	admission []byte,
+) (carrier.Conn, error) {
+	class, err := winn3ClassNamed(profile.Carrier.Class)
+	if err != nil {
+		return nil, err
+	}
+	dialCtx, cancel := context.WithTimeout(ctx, winn3DialTimeout)
+	defer cancel()
+
+	role := carrier.RoleClient
+	if profile.Role == winn3RoleGateway {
+		role = carrier.RoleGateway
+	}
+
+	switch class {
+	case carrier.ClassUDP:
+		remote, resolveErr := net.ResolveUDPAddr("udp", profile.Carrier.Endpoint)
+		if resolveErr != nil {
+			return nil, fmt.Errorf("carrier.endpoint: %w", resolveErr)
+		}
+		return carrier.DialUDP(dialCtx, carrier.UDPConfig{
+			Remote:         remote,
+			MaxMessageSize: sizing.MessageSize,
+			PathMTU:        sizing.PathMTU,
+			SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
+				fmt.Fprintf(os.Stderr, "winn-datapath: %s\n",
+					carrier.FormatUDPSocketBufferGrant(requested, gotRead, gotWrite, setErr))
+			},
+		})
+	case carrier.ClassTCP:
+		return carrier.DialStream(dialCtx,
+			carrier.DialTCP(profile.Carrier.Endpoint),
+			carrier.StreamConfig{
+				Secret:         admission,
+				Role:           role,
+				MaxMessageSize: sizing.MessageSize,
+				PathMTU:        sizing.PathMTU,
+			})
+	case carrier.ClassTLS:
+		return winn3DialTLS(dialCtx, profile, sizing, admission, role)
+	default:
+		return nil, winn3Refuse("carrier.class %s", class)
+	}
+}
+
+func winn3DialTLS(
+	ctx context.Context,
+	profile winn3Profile,
+	sizing driver.Sizing,
+	admission []byte,
+	role carrier.Role,
+) (carrier.Conn, error) {
+	suite, err := tlsconfig.ParseSuite(profile.Carrier.Suite)
+	if err != nil {
+		return nil, winn3Refuse("carrier.suite: %v", err)
+	}
+	alpn := profile.Carrier.tlsALPN()
+	trust := tlsconfig.ClientTrust{
+		Anchor:     tlsconfig.TrustAnchor(profile.Carrier.TrustAnchor),
+		RootCAPath: profile.Carrier.RootCAPath,
+	}
+	var clientTLS *tls.Config
+	if trust.Anchor == tlsconfig.TrustWebPKI {
+		clientTLS, err = tlsconfig.ClientAnonymousTrusted(
+			trust, profile.Carrier.ServerName, suite, alpn)
+	} else {
+		clientTLS, err = tlsconfig.ClientForALPN(
+			profile.Carrier.ClientCertPath,
+			profile.Carrier.ClientKeyPath,
+			profile.Carrier.RootCAPath,
+			profile.Carrier.ServerName,
+			suite,
+			alpn,
+		)
+	}
+	if err != nil {
+		return nil, fmt.Errorf("winn3 tls client: %w", err)
+	}
+	echList, err := echconfig.LoadClientConfigList(profile.Carrier.ECHConfigListPath)
+	if err != nil {
+		return nil, fmt.Errorf("winn3 tls ECH config list: %w", err)
+	}
+	err = echconfig.ConfigureClient(clientTLS, echList, true)
+	clear(echList)
+	if err != nil {
+		return nil, fmt.Errorf("winn3 tls ECH: %w", err)
+	}
+
+	endpoint := profile.Carrier.Endpoint
+	raw, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", endpoint)
+	if err != nil {
+		return nil, err
+	}
+	tlsConn, ok := raw.(*tls.Conn)
+	if !ok {
+		_ = raw.Close()
+		return nil, winn3Refuse(
+			"dialled class tls but the connection is %T: refusing a silent downgrade",
+			raw)
+	}
+	state := tlsConn.ConnectionState()
+	if !state.ECHAccepted {
+		_ = tlsConn.Close()
+		return nil, winn3Refuse("dialled class tls but ECH was not accepted")
+	}
+	if err := tlsconfig.ValidateStateForALPN(&state, suite, alpn); err != nil {
+		_ = tlsConn.Close()
+		return nil, winn3Refuse("winn3 tls handshake: %v", err)
+	}
+	stream, err := carrier.NewStream(carrier.StreamConfig{
+		Conn:           tlsConn,
+		Secret:         admission,
+		Role:           role,
+		MaxMessageSize: sizing.MessageSize,
+		PathMTU:        sizing.PathMTU,
+	})
+	if err != nil {
+		_ = tlsConn.Close()
+		return nil, err
+	}
+	if stream.Class() != carrier.ClassTLS {
+		_ = stream.Close()
+		return nil, winn3Refuse(
+			"dialled class tls but the stream is %s: refusing a silent downgrade",
+			stream.Class())
+	}
+	return stream, nil
+}
```

### winn_protocol_experimental/winn3/hostqueue/keys.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/hostqueue/keys.go
@@ -0,0 +1,97 @@
+// SPDX-License-Identifier: MIT
+// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
+// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
+package hostqueue
+
+import (
+	"bytes"
+	"encoding/hex"
+	"fmt"
+	"strings"
+
+	"winsvpn.local/winnprotocol/internal/securefile"
+	"winsvpn.local/winnprotocol/winn3/core"
+	"winsvpn.local/winnprotocol/winn3/dualsign"
+	"winsvpn.local/winnprotocol/winn3/session"
+)
+
+const winn3KeyFileMaxBytes = 8 << 10
+
+// ReadPrivateKeyFile uses the existing bounded custody-checked key reader.
+func ReadPrivateKeyFile(path, field string) ([]byte, error) {
+	raw, err := securefile.ReadPrivateLimited(path, winn3KeyFileMaxBytes)
+	if err != nil {
+		return nil, fmt.Errorf("%s: %w", field, err)
+	}
+	return raw, nil
+}
+
+// ApplyDualAuthPublics loads both attestation publics or refuses a partial pair.
+// Both absent remains the legacy desktop policy; Open requires both paths.
+func ApplyDualAuthPublics(cfg *session.Config, edPath, mlPath string) error {
+	edPath = strings.TrimSpace(edPath)
+	mlPath = strings.TrimSpace(mlPath)
+	if (edPath == "") != (mlPath == "") {
+		return fmt.Errorf(
+			"dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path must be set together")
+	}
+	if edPath == "" {
+		return nil
+	}
+	edPub, err := ReadDualAuthPublic(
+		edPath, dualsign.Ed25519PublicKeySize, "dual_auth_ed25519_pub_path")
+	if err != nil {
+		return err
+	}
+	mlPub, err := ReadDualAuthPublic(
+		mlPath, dualsign.MLDSA65PublicKeySize, "dual_auth_mldsa65_pub_path")
+	if err != nil {
+		return err
+	}
+	cfg.DualAuth = session.DualAuthConfig{
+		Expected:      true,
+		Ed25519Public: edPub,
+		MLDSA65Public: mlPub,
+	}
+	return nil
+}
+
+// ReadDualAuthPublic validates the protected file encoding and exact key size.
+func ReadDualAuthPublic(path string, want int, field string) ([]byte, error) {
+	raw, err := ReadPrivateKeyFile(path, field)
+	if err != nil {
+		return nil, err
+	}
+	decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
+	if err != nil {
+		return nil, fmt.Errorf("%s: %w", field, err)
+	}
+	if len(decoded) != want {
+		return nil, fmt.Errorf("%s: got %d bytes, want %d", field, len(decoded), want)
+	}
+	return decoded, nil
+}
+
+// ReadKeyFile accepts the existing raw or hex X25519 file encodings.
+func ReadKeyFile(path, field string) ([]byte, error) {
+	raw, err := ReadPrivateKeyFile(path, field)
+	if err != nil {
+		return nil, err
+	}
+	trimmed := bytes.TrimSpace(raw)
+	if len(trimmed) == hex.EncodedLen(core.KeySize) {
+		decoded, decodeErr := hex.DecodeString(string(trimmed))
+		if decodeErr == nil {
+			return decoded, nil
+		}
+	}
+	if len(raw) == core.KeySize {
+		return raw, nil
+	}
+	if len(trimmed) == core.KeySize {
+		return trimmed, nil
+	}
+	return nil, fmt.Errorf(
+		"%s: %d bytes; expected %d raw bytes or %d hex characters",
+		field, len(raw), core.KeySize, hex.EncodedLen(core.KeySize))
+}
```

### winn_protocol_experimental/winn3/hostqueue/profile.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/hostqueue/profile.go
@@ -0,0 +1,587 @@
+// SPDX-License-Identifier: MIT
+// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
+// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
+package hostqueue
+
+import (
+	"bytes"
+	"encoding/json"
+	"errors"
+	"fmt"
+	"io"
+	"net/netip"
+	"strings"
+	"winsvpn.local/winnprotocol/internal/securefile"
+
+	"winsvpn.local/winnprotocol/internal/tlsconfig"
+	"winsvpn.local/winnprotocol/winn3/carrier"
+)
+
+const winn3ProfileVersion = "winn3-host/1"
+
+const maxWinn3ProfileBytes = 64 << 10
+
+const maxWinn3ProfileJSONDepth = 8
+
+const maxWinn3PathMTU = 65535
+
+const maxWinn3PlanEntries = 3
+
+type winn3Profile struct {
+	Version string `json:"version"`
+
+	Role string `json:"role"`
+
+	Plan []string `json:"plan"`
+
+	PathMTU int `json:"path_mtu"`
+
+	GatewayID string `json:"gateway_id"`
+
+	Carrier winn3CarrierSpec `json:"carrier"`
+	Inner   winn3InnerSpec   `json:"inner"`
+	Keys    winn3KeySpec     `json:"keys"`
+	Device  winn3DeviceSpec  `json:"device"`
+
+	AllowOwnSocket bool `json:"allow_own_socket"`
+
+	OuterSocketExclusion string `json:"outer_socket_exclusion"`
+
+	FastPQ bool `json:"fast_pq"`
+}
+
+type winn3CarrierSpec struct {
+	Class string `json:"class"`
+
+	Endpoint string `json:"endpoint"`
+
+	TrustAnchor string `json:"trust_anchor,omitempty"`
+
+	RootCAPath string `json:"root_ca_path,omitempty"`
+
+	ECHConfigListPath string `json:"ech_config_list_path,omitempty"`
+
+	ClientCertPath string `json:"client_cert_path,omitempty"`
+	ClientKeyPath  string `json:"client_key_path,omitempty"`
+
+	ServerName string `json:"server_name,omitempty"`
+
+	Suite string `json:"suite,omitempty"`
+
+	ALPN string `json:"alpn,omitempty"`
+}
+
+type winn3InnerSpec struct {
+	V4       string `json:"v4"`
+	V6       string `json:"v6"`
+	RouterV4 string `json:"router_v4"`
+	RouterV6 string `json:"router_v6"`
+}
+
+type winn3KeySpec struct {
+	StaticPath string `json:"static_path"`
+
+	GatewayStaticPath string `json:"gateway_static_path"`
+
+	AdmissionPath string `json:"admission_path"`
+
+	DualAuthEd25519PubPath string `json:"dual_auth_ed25519_pub_path"`
+	DualAuthMLDSA65PubPath string `json:"dual_auth_mldsa65_pub_path"`
+}
+
+type winn3DeviceSpec struct {
+	Kind string `json:"kind"`
+
+	HostPort int `json:"host_port"`
+
+	Name string `json:"name"`
+}
+
+const (
+	winn3DeviceLoopbackUDP = "loopback-udp"
+	winn3DeviceTunFD       = "tun-fd"
+	winn3RoleClient        = "client"
+	winn3RoleGateway       = "gateway"
+
+	winn3TLSDefaultALPN = "h2"
+)
+
+var errWinn3Profile = errors.New("winn3 host profile")
+
+func winn3Refuse(format string, args ...any) error {
+	return fmt.Errorf("%w: %s", errWinn3Profile, fmt.Sprintf(format, args...))
+}
+
+func loadWinn3Profile(path string) (winn3Profile, error) {
+	raw, err := readWinn3ProfileFile(path)
+	if err != nil {
+		return winn3Profile{}, err
+	}
+	if depth := winn3JSONNestingDepth(raw); depth > maxWinn3ProfileJSONDepth {
+		return winn3Profile{}, winn3Refuse(
+			"JSON nesting depth %d exceeds %d", depth, maxWinn3ProfileJSONDepth)
+	}
+	if key := winn3DuplicateJSONMember(raw); key != "" {
+		return winn3Profile{}, winn3Refuse("duplicate JSON member %q", key)
+	}
+	decoder := json.NewDecoder(strings.NewReader(string(raw)))
+	decoder.DisallowUnknownFields()
+	var profile winn3Profile
+	if err := decoder.Decode(&profile); err != nil {
+		return winn3Profile{}, fmt.Errorf("decode winn3 profile %q: %w", path, err)
+	}
+	if decoder.Decode(new(any)) != io.EOF {
+		return winn3Profile{}, winn3Refuse("document must be a single JSON object")
+	}
+	if err := profile.validate(); err != nil {
+		return winn3Profile{}, err
+	}
+	return profile, nil
+}
+
+func readWinn3ProfileFile(path string) ([]byte, error) {
+	return securefile.ReadPrivateLimited(path, maxWinn3ProfileBytes)
+}
+
+func winn3JSONNestingDepth(raw []byte) int {
+	depth, maxDepth := 0, 0
+	inString := false
+	escaped := false
+	for _, b := range raw {
+		if inString {
+			if escaped {
+				escaped = false
+				continue
+			}
+			if b == '\\' {
+				escaped = true
+				continue
+			}
+			if b == '"' {
+				inString = false
+			}
+			continue
+		}
+		switch b {
+		case '"':
+			inString = true
+		case '{', '[':
+			depth++
+			if depth > maxDepth {
+				maxDepth = depth
+			}
+		case '}', ']':
+			if depth > 0 {
+				depth--
+			}
+		}
+	}
+	return maxDepth
+}
+
+func winn3DuplicateJSONMember(raw []byte) string {
+	decoder := json.NewDecoder(bytes.NewReader(raw))
+	key, err := winn3ScanDuplicateJSONMember(decoder)
+	if err != nil {
+		return ""
+	}
+	return key
+}
+
+func winn3ScanDuplicateJSONMember(decoder *json.Decoder) (string, error) {
+	token, err := decoder.Token()
+	if err != nil {
+		return "", err
+	}
+	delim, ok := token.(json.Delim)
+	if !ok {
+		return "", nil
+	}
+	switch delim {
+	case '{':
+		seen := make(map[string]struct{})
+		for decoder.More() {
+			keyToken, err := decoder.Token()
+			if err != nil {
+				return "", err
+			}
+			key, ok := keyToken.(string)
+			if !ok {
+				return "", errors.New("JSON object key is not a string")
+			}
+			if _, exists := seen[strings.ToLower(key)]; exists {
+				return key, nil
+			}
+			seen[strings.ToLower(key)] = struct{}{}
+			dup, err := winn3ScanDuplicateJSONMember(decoder)
+			if err != nil || dup != "" {
+				return dup, err
+			}
+		}
+		_, err := decoder.Token()
+		return "", err
+	case '[':
+		for decoder.More() {
+			dup, err := winn3ScanDuplicateJSONMember(decoder)
+			if err != nil || dup != "" {
+				return dup, err
+			}
+		}
+		_, err := decoder.Token()
+		return "", err
+	default:
+		return "", fmt.Errorf("unexpected JSON delimiter %q", delim)
+	}
+}
+
+func (p winn3Profile) classes() ([]carrier.Class, error) {
+	out := make([]carrier.Class, 0, len(p.Plan))
+	for i, name := range p.Plan {
+		class, err := winn3ClassNamed(name)
+		if err != nil {
+			return nil, winn3Refuse("plan entry %d: %v", i, err)
+		}
+		out = append(out, class)
+	}
+	return out, nil
+}
+
+func winn3ClassNamed(name string) (carrier.Class, error) {
+	switch strings.TrimSpace(name) {
+	case carrier.ClassUDP.String():
+		return carrier.ClassUDP, nil
+	case carrier.ClassTCP.String():
+		return carrier.ClassTCP, nil
+	case carrier.ClassTLS.String():
+		return carrier.ClassTLS, nil
+	default:
+		return carrier.ClassUnknown, fmt.Errorf(
+			"unknown carrier class %q; use %s, %s or %s",
+			name, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS,
+		)
+	}
+}
+
+func (p winn3Profile) validate() error {
+	if p.Version != winn3ProfileVersion {
+		return winn3Refuse("version is %q, this build speaks %q",
+			p.Version, winn3ProfileVersion)
+	}
+	if p.Role != winn3RoleClient && p.Role != winn3RoleGateway {
+		return winn3Refuse("role is %q; use %q or %q",
+			p.Role, winn3RoleClient, winn3RoleGateway)
+	}
+
+	if !p.AllowOwnSocket {
+		return winn3Refuse(
+			"allow_own_socket is false: this mode opens the outer socket " +
+				"itself and has no descriptor hand-off, so a host that has not " +
+				"installed a route exclusion must not start it")
+	}
+	if strings.TrimSpace(p.OuterSocketExclusion) == "" {
+		return winn3Refuse(
+			"allow_own_socket is true but outer_socket_exclusion is empty: " +
+				"name the exclusion that keeps the engine's own socket out of " +
+				"the tunnel it carries")
+	}
+
+	if len(p.Plan) == 0 {
+		return winn3Refuse(
+			"plan is empty: name every carrier class this session may " +
+				"escalate to, because the message floor is computed over it")
+	}
+	if len(p.Plan) > maxWinn3PlanEntries {
+		return winn3Refuse(
+			"plan has %d entries; this build knows %d carrier classes",
+			len(p.Plan), maxWinn3PlanEntries)
+	}
+	classes, err := p.classes()
+	if err != nil {
+		return err
+	}
+	seen := make(map[carrier.Class]bool, len(classes))
+	for _, class := range classes {
+		if seen[class] {
+			return winn3Refuse("plan names %s twice", class)
+		}
+		seen[class] = true
+	}
+	if p.PathMTU < 0 {
+		return winn3Refuse("path_mtu %d is negative", p.PathMTU)
+	}
+	if p.PathMTU > maxWinn3PathMTU {
+		return winn3Refuse(
+			"path_mtu %d exceeds %d, the largest IP datagram",
+			p.PathMTU, maxWinn3PathMTU)
+	}
+
+	dialled, err := winn3ClassNamed(p.Carrier.Class)
+	if err != nil {
+		return winn3Refuse("carrier.class: %v", err)
+	}
+	planned := false
+	for _, c := range classes {
+		if c == dialled {
+			planned = true
+			break
+		}
+	}
+	if !planned {
+		return winn3Refuse(
+			"carrier.class %s is not named in the plan %v: the floor was not "+
+				"computed over it", dialled, p.Plan)
+	}
+	if err := winn3ValidateEndpoint(p.Carrier.Endpoint); err != nil {
+		return winn3Refuse("carrier.endpoint: %v", err)
+	}
+	if err := p.Carrier.validateTLS(dialled); err != nil {
+		return err
+	}
+
+	if _, err := p.Inner.assignmentAddrs(); err != nil {
+		return err
+	}
+
+	if strings.TrimSpace(p.GatewayID) == "" {
+		return winn3Refuse(
+			"gateway_id is empty: without it an initiation captured at one " +
+				"gateway replays at another that shares the admission key")
+	}
+	if strings.TrimSpace(p.Keys.StaticPath) == "" {
+		return winn3Refuse("keys.static_path is empty")
+	}
+	if strings.TrimSpace(p.Keys.AdmissionPath) == "" {
+		return winn3Refuse("keys.admission_path is empty")
+	}
+	switch p.Role {
+	case winn3RoleClient:
+		if strings.TrimSpace(p.Keys.GatewayStaticPath) == "" {
+			return winn3Refuse(
+				"keys.gateway_static_path is empty: a client authenticates " +
+					"the gateway by its static key and there is no anonymous mode")
+		}
+	case winn3RoleGateway:
+		if strings.TrimSpace(p.Keys.GatewayStaticPath) != "" {
+			return winn3Refuse(
+				"keys.gateway_static_path is set on a gateway; it is the " +
+					"client's field")
+		}
+	}
+
+	if p.Device.Kind != "wintun-direct" || p.Device.HostPort != 0 || p.Device.Name != "winsvpn3" {
+		return winn3Refuse("direct candidate requires device.kind=wintun-direct, name=winsvpn3, and no host_port")
+	}
+	if p.Role != winn3RoleClient || p.FastPQ {
+		return winn3Refuse("direct candidate requires client role and strict PQ")
+	}
+	if strings.TrimSpace(p.Keys.DualAuthEd25519PubPath) == "" || strings.TrimSpace(p.Keys.DualAuthMLDSA65PubPath) == "" {
+		return winn3Refuse("direct candidate requires both gateway dual-auth public key paths")
+	}
+
+	return nil
+}
+
+func winn3ValidateEndpoint(endpoint string) error {
+	if strings.TrimSpace(endpoint) == "" {
+		return errors.New("empty")
+	}
+	parsed, err := netip.ParseAddrPort(endpoint)
+	if err != nil {
+		return fmt.Errorf(
+			"%q is not an IP literal with a port (a hostname would be a DNS "+
+				"lookup on the censored path): %w", endpoint, err)
+	}
+	if parsed.Port() == 0 {
+		return fmt.Errorf("%q has port 0", endpoint)
+	}
+	ip := parsed.Addr()
+	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || winn3LimitedBroadcast(ip) {
+		return fmt.Errorf("%q is not a unicast IP literal", endpoint)
+	}
+	return nil
+}
+
+func winn3LimitedBroadcast(ip netip.Addr) bool {
+	return ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255}
+}
+
+func (s winn3InnerSpec) assignmentAddrs() (winn3Assignment, error) {
+	var out winn3Assignment
+	parse := func(field, value string, want4 bool) (netip.Addr, error) {
+		if strings.TrimSpace(value) == "" {
+			return netip.Addr{}, nil
+		}
+		addr, err := netip.ParseAddr(value)
+		if err != nil {
+			return netip.Addr{}, winn3Refuse("inner.%s: %v", field, err)
+		}
+		if addr.Zone() != "" {
+			return netip.Addr{}, winn3Refuse(
+				"inner.%s carries a zone; the inner address space has no "+
+					"link-local scope", field)
+		}
+		if want4 != addr.Is4() {
+			return netip.Addr{}, winn3Refuse(
+				"inner.%s is %q, which is not the expected family", field, value)
+		}
+		return addr, nil
+	}
+	var err error
+	if out.V4, err = parse("v4", s.V4, true); err != nil {
+		return winn3Assignment{}, err
+	}
+	if out.V6, err = parse("v6", s.V6, false); err != nil {
+		return winn3Assignment{}, err
+	}
+	if out.RouterV4, err = parse("router_v4", s.RouterV4, true); err != nil {
+		return winn3Assignment{}, err
+	}
+	if out.RouterV6, err = parse("router_v6", s.RouterV6, false); err != nil {
+		return winn3Assignment{}, err
+	}
+	if !out.V4.IsValid() && !out.V6.IsValid() {
+		return winn3Assignment{}, winn3Refuse(
+			"inner carries neither an IPv4 nor an IPv6 address")
+	}
+	return out, nil
+}
+
+type winn3Assignment struct {
+	V4       netip.Addr
+	V6       netip.Addr
+	RouterV4 netip.Addr
+	RouterV6 netip.Addr
+}
+
+func (p winn3Profile) describeForLog() string {
+	var b strings.Builder
+	b.WriteString("winn3 profile version=")
+	b.WriteString(p.Version)
+	b.WriteString(" role=")
+	b.WriteString(p.Role)
+	b.WriteString(" carrier=")
+	b.WriteString(p.Carrier.Class)
+	b.WriteString(" plan=")
+	b.WriteString(strings.Join(p.Plan, "+"))
+	fmt.Fprintf(&b, " path_mtu=%d device=%s inner_v4=%t inner_v6=%t",
+		p.PathMTU, p.Device.Kind, strings.TrimSpace(p.Inner.V4) != "",
+		strings.TrimSpace(p.Inner.V6) != "")
+	fmt.Fprintf(&b, " allow_own_socket=%t exclusion_declared=%t fast_pq=%t",
+		p.AllowOwnSocket,
+		strings.TrimSpace(p.OuterSocketExclusion) != "", p.FastPQ)
+	if p.Carrier.Class == carrier.ClassTLS.String() {
+		fmt.Fprintf(&b, " trust=%s ech_list=%t client_cert=%t",
+			strings.TrimSpace(p.Carrier.TrustAnchor),
+			strings.TrimSpace(p.Carrier.ECHConfigListPath) != "",
+			strings.TrimSpace(p.Carrier.ClientCertPath) != "")
+	}
+	return b.String()
+}
+
+func (c winn3CarrierSpec) validateTLS(dialled carrier.Class) error {
+	if name := c.firstTLSFieldSet(); name != "" && dialled != carrier.ClassTLS {
+		return winn3Refuse(
+			"carrier.%s is set but carrier.class is %s: TLS material applies "+
+				"to class tls only", name, dialled)
+	}
+	if dialled != carrier.ClassTLS {
+		return nil
+	}
+
+	anchor := strings.TrimSpace(c.TrustAnchor)
+	if anchor == "" {
+		return winn3Refuse(
+			"carrier.class tls requires trust_anchor: use %s or %s; an "+
+				"absent field has not stated what the client verifies the "+
+				"server certificate against",
+			tlsconfig.TrustPrivateCA, tlsconfig.TrustWebPKI)
+	}
+	if strings.TrimSpace(c.ServerName) == "" {
+		return winn3Refuse(
+			"carrier.class tls requires server_name: it is the inner " +
+				"ClientHello name, under ECH")
+	}
+	if strings.TrimSpace(c.Suite) == "" {
+		return winn3Refuse(
+			"carrier.class tls requires suite: tlsconfig.ParseSuite is the " +
+				"authority on the list")
+	}
+	suite, err := tlsconfig.ParseSuite(c.Suite)
+	if err != nil {
+		return winn3Refuse("carrier.suite: %v", err)
+	}
+	if strings.TrimSpace(c.ECHConfigListPath) == "" {
+		return winn3Refuse(
+			"carrier.class tls requires ech_config_list_path: without it " +
+				"the ClientHello is a single-probe fingerprint")
+	}
+
+	switch tlsconfig.TrustAnchor(anchor) {
+	case tlsconfig.TrustPrivateCA:
+		if strings.TrimSpace(c.RootCAPath) == "" {
+			return winn3Refuse(
+				"carrier.class tls with trust_anchor %s requires root_ca_path",
+				tlsconfig.TrustPrivateCA)
+		}
+		if strings.TrimSpace(c.ClientCertPath) == "" {
+			return winn3Refuse(
+				"carrier.class tls with trust_anchor %s requires client_cert_path",
+				tlsconfig.TrustPrivateCA)
+		}
+		if strings.TrimSpace(c.ClientKeyPath) == "" {
+			return winn3Refuse(
+				"carrier.class tls with trust_anchor %s requires client_key_path",
+				tlsconfig.TrustPrivateCA)
+		}
+	case tlsconfig.TrustWebPKI:
+		if strings.TrimSpace(c.RootCAPath) != "" {
+			return fmt.Errorf("%w: %w: carrier.root_ca_path is set",
+				errWinn3Profile, tlsconfig.ErrTrustRootCAConflict)
+		}
+		if strings.TrimSpace(c.ClientCertPath) != "" ||
+			strings.TrimSpace(c.ClientKeyPath) != "" {
+			return fmt.Errorf("%w: %w: carrier.client_cert_path / "+
+				"carrier.client_key_path are set",
+				errWinn3Profile, tlsconfig.ErrTrustWebPKIWithClientCertificate)
+		}
+		if _, err := tlsconfig.ClientAnonymousTrusted(
+			tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
+			c.ServerName, suite, c.tlsALPN(),
+		); err != nil {
+			return fmt.Errorf("%w: %w", errWinn3Profile, err)
+		}
+	default:
+		return fmt.Errorf("%w: %w (got %q)",
+			errWinn3Profile, tlsconfig.ErrTrustAnchorUnknown, anchor)
+	}
+	return nil
+}
+
+func (c winn3CarrierSpec) firstTLSFieldSet() string {
+	fields := []struct {
+		name  string
+		value string
+	}{
+		{"trust_anchor", c.TrustAnchor},
+		{"root_ca_path", c.RootCAPath},
+		{"ech_config_list_path", c.ECHConfigListPath},
+		{"client_cert_path", c.ClientCertPath},
+		{"client_key_path", c.ClientKeyPath},
+		{"server_name", c.ServerName},
+		{"suite", c.Suite},
+		{"alpn", c.ALPN},
+	}
+	for _, field := range fields {
+		if strings.TrimSpace(field.value) != "" {
+			return field.name
+		}
+	}
+	return ""
+}
+
+func (c winn3CarrierSpec) tlsALPN() string {
+	if name := strings.TrimSpace(c.ALPN); name != "" {
+		return name
+	}
+	return winn3TLSDefaultALPN
+}
```

### winn_protocol_experimental/winn3/hostqueue/runtime.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/hostqueue/runtime.go
@@ -0,0 +1,263 @@
+// Package hostqueue hosts the strict Winn client with a directly attached host
+// device. Despite the package name it uses no inner packet queue or socket.
+// The privileged host retains descriptor authentication and route authority.
+package hostqueue
+
+import (
+	"context"
+	"errors"
+	"fmt"
+	"io"
+	"sync"
+	"time"
+
+	"winsvpn.local/winnprotocol/winn3/carrier"
+	"winsvpn.local/winnprotocol/winn3/driver"
+	"winsvpn.local/winnprotocol/winn3/tun"
+)
+
+// Device.Close must wake ReadPacket, prevent further device access, and wait
+// for existing device calls before releasing native resources. WritePacket
+// must return an error if a packet was not actually accepted by the host.
+type Device interface {
+	tun.Device
+	io.Closer
+}
+
+// Runtime owns one carrier, one session and one host device. Open constructs
+// everything before Run starts packet processing. Call Run once, then Close.
+type Runtime struct {
+	loop      *driver.Loop
+	device    *attachedDevice
+	sizing    driver.Sizing
+	exclusion string
+	closeOnce sync.Once
+	closeErr  error
+	stateMu   sync.Mutex
+	started   bool
+	closed    bool
+}
+
+// attachedDevice lets the real session constructor validate the complete
+// configuration before the host creates an adapter. Publication happens before
+// Run, so no device method can race with attachment.
+type attachedDevice struct {
+	Device
+	mtu       int
+	failed    chan error
+	closeOnce sync.Once
+	closeErr  error
+}
+
+func (d *attachedDevice) MTU() int { return d.mtu }
+func (d *attachedDevice) Close() error {
+	d.closeOnce.Do(func() { d.closeErr = d.Device.Close() })
+	return d.closeErr
+}
+func (d *attachedDevice) ReadPacket(buf []byte) (int, error) {
+	n, err := d.Device.ReadPacket(buf)
+	if err != nil {
+		select {
+		case d.failed <- err:
+		default:
+		}
+	}
+	return n, err
+}
+
+// Open accepts only a protected, strict-PQ client profile with both gateway
+// attestation keys and device kind wintun-direct. The upstream securefile
+// readers enforce custody on the profile and every key file. The authenticated
+// supervisor must install the outer route exclusion before calling Open.
+// This function never authenticates a served descriptor or installs routes.
+func Open(ctx context.Context, profilePath string, factory func(int) (Device, error)) (*Runtime, error) {
+	if factory == nil {
+		return nil, errors.New("direct host: nil device factory")
+	}
+	if err := ctx.Err(); err != nil {
+		return nil, err
+	}
+	profile, err := loadWinn3Profile(profilePath)
+	if err != nil {
+		return nil, err
+	}
+	classes, err := profile.classes()
+	if err != nil {
+		return nil, err
+	}
+	pathMTU := profile.PathMTU
+	if pathMTU == 0 {
+		pathMTU = carrier.DefaultPathMTU
+	}
+	sizing, err := driver.NewSizing(pathMTU, classes...)
+	if err != nil {
+		return nil, err
+	}
+	cfg, admission, err := winn3BuildSession(profile)
+	if err != nil {
+		return nil, err
+	}
+	assignment, err := profile.Inner.assignmentAddrs()
+	if err != nil {
+		return nil, err
+	}
+	device := &attachedDevice{mtu: sizing.InnerMTU, failed: make(chan error, 1)}
+	tunConfig := tun.Config{
+		Assign: tun.Assignment{V4: assignment.V4, V6: assignment.V6,
+			RouterV4: assignment.RouterV4, RouterV6: assignment.RouterV6},
+		Device: device,
+		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
+	}
+	// Validate the actual session/tun constructors before dialing or creating
+	// the native adapter. The pipe cannot emit anything. A second key read
+	// below avoids reusing material wiped by the probe's orderly Close.
+	probeCarrier, err := carrier.NewPipe(carrier.PipeConfig{
+		Class: classes[0], MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
+		Out: func([]byte) error { return errors.New("direct preflight cannot send") },
+	})
+	if err != nil {
+		return nil, err
+	}
+	probe, err := driver.NewClient(driver.Config{Session: cfg, Sizing: sizing, Carrier: probeCarrier, Tun: &tunConfig})
+	if err != nil {
+		_ = probeCarrier.Close()
+		return nil, err
+	}
+	closeUnstartedLoop(probe)
+	cfg, admission, err = winn3BuildSession(profile)
+	if err != nil {
+		return nil, err
+	}
+	conn, err := winn3DialCarrier(ctx, profile, sizing, admission)
+	if err != nil {
+		return nil, err
+	}
+	loop, err := driver.NewClient(driver.Config{Session: cfg, Sizing: sizing, Carrier: conn, Tun: &tunConfig})
+	if err != nil {
+		_ = conn.Close()
+		return nil, err
+	}
+	if err := ctx.Err(); err != nil {
+		closeUnstartedLoop(loop)
+		return nil, err
+	}
+	native, err := factory(sizing.InnerMTU)
+	if err != nil {
+		if native != nil {
+			_ = native.Close()
+		}
+		closeUnstartedLoop(loop)
+		return nil, err
+	}
+	if native == nil {
+		closeUnstartedLoop(loop)
+		return nil, errors.New("direct host: nil device")
+	}
+	if native.MTU() != sizing.InnerMTU {
+		_ = native.Close()
+		closeUnstartedLoop(loop)
+		return nil, errors.New("direct host: device MTU differs from plan floor")
+	}
+	device.Device = native
+	r := &Runtime{loop: loop, device: device, sizing: sizing, exclusion: profile.OuterSocketExclusion}
+	if err := ctx.Err(); err != nil {
+		_ = r.Close()
+		return nil, err
+	}
+	return r, nil
+}
+
+// Run publishes the same promotion predicate as the desktop engine: carrying
+// gate plus a successful validated device delivery. Cancellation or a failed
+// device read stops the engine and closes the native device. The caller must
+// bound its output writer; Windows additionally enforces a process exit bound.
+func (r *Runtime) Run(ctx context.Context, out io.Writer) error {
+	r.stateMu.Lock()
+	if r.closed || r.started {
+		r.stateMu.Unlock()
+		return errors.New("direct host: runtime closed or already run")
+	}
+	r.started = true
+	r.stateMu.Unlock()
+	ctx, cancel := context.WithCancel(ctx)
+	defer cancel()
+	done := make(chan error, 1)
+	go func() { done <- r.loop.Run(ctx) }()
+	closed := make(chan struct{})
+	stopClose := context.AfterFunc(ctx, func() { _ = r.device.Close(); close(closed) })
+	defer func() {
+		cancel()
+		if !stopClose() {
+			<-closed
+		}
+		_ = r.Close()
+	}()
+	promoted := false
+	write := func(event string, runErr error) error {
+		status := winn3StatusFrom(event, r.loop, r.sizing, r.exclusion)
+		if event == "posture" && status.PromotionReady && !promoted {
+			status.Event = "carrying"
+			promoted = true
+		}
+		if event == "stopped" {
+			status.PromotionReady = false
+			status.Posture = winn3PostureBootstrap
+			if runErr != nil {
+				status.Refusal = "direct engine stopped"
+			}
+		}
+		return winn3WriteStatus(out, status)
+	}
+	if err := write("posture", nil); err != nil {
+		cancel()
+		<-done
+		return err
+	}
+	ticker := time.NewTicker(time.Second)
+	defer ticker.Stop()
+	var deviceErr error
+	failed := r.device.failed
+	for {
+		select {
+		case err := <-done:
+			if deviceErr != nil {
+				err = fmt.Errorf("direct host read: %w", deviceErr)
+			}
+			if writeErr := write("stopped", err); writeErr != nil {
+				return writeErr
+			}
+			return err
+		case deviceErr = <-failed:
+			failed = nil
+			cancel()
+		case <-ticker.C:
+			if err := write("posture", nil); err != nil {
+				cancel()
+				<-done
+				return err
+			}
+		}
+	}
+}
+
+func (r *Runtime) Close() error {
+	r.closeOnce.Do(func() {
+		r.stateMu.Lock()
+		r.closed = true
+		r.stateMu.Unlock()
+		// Device.Close wakes the outbound reader even though Loop.Run does not
+		// join that goroutine. Later device calls see a closed device, not a
+		// freed Wintun ring.
+		r.closeErr = r.device.Close()
+		r.closeErr = errors.Join(r.closeErr, r.loop.Close())
+		r.closeErr = errors.Join(r.closeErr, r.loop.Carrier().Close())
+	})
+	return r.closeErr
+}
+
+// Closing an unstarted client terminates and wipes its initiator immediately,
+// but Loop.Close does not close the carrier. No run goroutine exists to do so.
+func closeUnstartedLoop(loop *driver.Loop) {
+	_ = loop.Close()
+	_ = loop.Carrier().Close()
+}
```

### winn_protocol_experimental/winn3/hostqueue/runtime_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/hostqueue/runtime_test.go
@@ -0,0 +1,520 @@
+package hostqueue
+
+import (
+	"bytes"
+	"context"
+	"crypto/ed25519"
+	"crypto/rand"
+	"encoding/binary"
+	"encoding/hex"
+	"encoding/json"
+	"errors"
+	"io"
+	"net"
+	"net/netip"
+	"os"
+	"path/filepath"
+	"strings"
+	"sync"
+	"sync/atomic"
+	"testing"
+	"time"
+
+	"winsvpn.local/winnprotocol/internal/pqauth"
+	"winsvpn.local/winnprotocol/internal/securefile"
+	"winsvpn.local/winnprotocol/winn3/carrier"
+	"winsvpn.local/winnprotocol/winn3/core"
+	"winsvpn.local/winnprotocol/winn3/driver"
+	"winsvpn.local/winnprotocol/winn3/session"
+	"winsvpn.local/winnprotocol/winn3/tun"
+)
+
+// Only ephemeral test keys are generated/read. No operator credentials or
+// real endpoints are used by any test in this package.
+func profileFixture(t *testing.T, endpoint string) (string, winn3Profile, session.Config) {
+	t.Helper()
+	dir := t.TempDir()
+	write := func(name string, b []byte) string {
+		path := filepath.Join(dir, name)
+		if err := securefile.AtomicWrite(path, b, 0600); err != nil {
+			t.Fatal(err)
+		}
+		return path
+	}
+	client, err := core.GenerateStaticKey()
+	if err != nil {
+		t.Fatal(err)
+	}
+	gateway, err := core.GenerateStaticKey()
+	if err != nil {
+		t.Fatal(err)
+	}
+	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
+	if err != nil {
+		t.Fatal(err)
+	}
+	mlSeed, err := pqauth.GenerateSeed()
+	if err != nil {
+		t.Fatal(err)
+	}
+	signer, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer signer.Destroy()
+	admission := bytes.Repeat([]byte{7}, 32)
+	p := winn3Profile{
+		Version: winn3ProfileVersion, Role: "client", Plan: []string{"udp", "tcp", "tls"},
+		PathMTU: carrier.DefaultPathMTU, GatewayID: "direct-host-test",
+		Carrier:        winn3CarrierSpec{Class: "udp", Endpoint: endpoint},
+		Inner:          winn3InnerSpec{V4: "10.64.0.2", RouterV4: "10.64.0.1"},
+		Device:         winn3DeviceSpec{Kind: "wintun-direct", Name: "winsvpn3"},
+		AllowOwnSocket: true, OuterSocketExclusion: "test fixture outer loopback route",
+		Keys: winn3KeySpec{
+			StaticPath: write("client.key", client.Bytes()), GatewayStaticPath: write("gateway.pub", gateway.Public()),
+			AdmissionPath:          write("admission.key", admission),
+			DualAuthEd25519PubPath: write("ed.pub", []byte(hex.EncodeToString(edPub))),
+			DualAuthMLDSA65PubPath: write("ml.pub", []byte(hex.EncodeToString(signer.PublicBytes()))),
+		},
+	}
+	raw, err := json.Marshal(p)
+	if err != nil {
+		t.Fatal(err)
+	}
+	return write("profile.json", raw), p, session.Config{
+		Static: gateway, Padding: core.PadBucket,
+		Core:     core.Config{Gateway: core.GatewayParams{AdmissionKeys: [][]byte{admission}, GatewayID: []byte(p.GatewayID)}},
+		Accept:   func([]byte) error { return nil },
+		DualAuth: session.DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed},
+	}
+}
+
+func writeProfile(t *testing.T, path string, p winn3Profile) {
+	t.Helper()
+	raw, err := json.Marshal(p)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if err := securefile.AtomicWrite(path, raw, 0600); err != nil {
+		t.Fatal(err)
+	}
+}
+
+func TestDirectConfigurationFailsBeforeAdapterCreation(t *testing.T) {
+	path, original, _ := profileFixture(t, "127.0.0.1:9")
+	for name, mutate := range map[string]func(*winn3Profile){
+		"no exclusion":          func(p *winn3Profile) { p.OuterSocketExclusion = "" },
+		"no authority":          func(p *winn3Profile) { p.AllowOwnSocket = false },
+		"fast PQ":               func(p *winn3Profile) { p.FastPQ = true },
+		"missing dual key":      func(p *winn3Profile) { p.Keys.DualAuthMLDSA65PubPath = "" },
+		"legacy relay":          func(p *winn3Profile) { p.Device.Kind = "loopback-udp"; p.Device.HostPort = 99 },
+		"stray port":            func(p *winn3Profile) { p.Device.HostPort = 99 },
+		"other adapter":         func(p *winn3Profile) { p.Device.Name = "winsvpn" },
+		"gateway role":          func(p *winn3Profile) { p.Role = "gateway" },
+		"DNS endpoint":          func(p *winn3Profile) { p.Carrier.Endpoint = "example.com:443" },
+		"router aliases client": func(p *winn3Profile) { p.Inner.RouterV4 = p.Inner.V4 },
+		"missing key file":      func(p *winn3Profile) { p.Keys.StaticPath = filepath.Join(t.TempDir(), "absent") },
+	} {
+		t.Run(name, func(t *testing.T) {
+			p := original
+			mutate(&p)
+			writeProfile(t, path, p)
+			called := false
+			r, err := Open(t.Context(), path, func(int) (Device, error) { called = true; return nil, errors.New("factory must not run") })
+			if r != nil || err == nil || called {
+				t.Fatalf("refusal failed: runtime=%v error=%v factory=%v", r != nil, err, called)
+			}
+		})
+	}
+}
+
+func TestDirectProfileRejectsDuplicateTrailingAndUnprotectedInput(t *testing.T) {
+	path, p, _ := profileFixture(t, "127.0.0.1:9")
+	raw, err := json.Marshal(p)
+	if err != nil {
+		t.Fatal(err)
+	}
+	for _, bad := range []string{
+		string(raw) + `{}`, string(raw) + ` broken`,
+		strings.Replace(string(raw), `"fast_pq":false`, `"fast_pq":true,"fast_pq":false`, 1),
+		strings.Replace(string(raw), `"fast_pq":false`, `"FAST_PQ":true,"fast_pq":false`, 1),
+		strings.Replace(string(raw), `"version":`, `"unknown":0,"version":`, 1),
+		strings.Repeat("[", 20) + "0" + strings.Repeat("]", 20),
+	} {
+		if err := securefile.AtomicWrite(path, []byte(bad), 0600); err != nil {
+			t.Fatal(err)
+		}
+		if _, err := loadWinn3Profile(path); err == nil {
+			t.Fatal("accepted ambiguous profile")
+		}
+	}
+	writeProfile(t, path, p)
+	link := filepath.Join(filepath.Dir(path), "link.json")
+	if err := os.Symlink(path, link); err != nil {
+		t.Fatal(err)
+	}
+	if _, err := loadWinn3Profile(link); err == nil {
+		t.Fatal("accepted symlink profile")
+	}
+}
+
+type testDevice struct {
+	mtu     int
+	read    chan []byte
+	written chan []byte
+	done    chan struct{}
+	once    sync.Once
+	closed  atomic.Int32
+	reject  atomic.Bool
+}
+
+func newTestDevice(mtu int) *testDevice {
+	return &testDevice{mtu: mtu, read: make(chan []byte, 4), written: make(chan []byte, 4), done: make(chan struct{})}
+}
+func (d *testDevice) MTU() int { return d.mtu }
+func (d *testDevice) ReadPacket(buf []byte) (int, error) {
+	select {
+	case p := <-d.read:
+		if len(buf) < len(p) {
+			return 0, io.ErrShortBuffer
+		}
+		return copy(buf, p), nil
+	case <-d.done:
+		return 0, io.ErrClosedPipe
+	}
+}
+func (d *testDevice) WritePacket(p []byte) (int, error) {
+	if d.reject.Load() {
+		return 0, errors.New("test native ring full")
+	}
+	select {
+	case d.written <- bytes.Clone(p):
+		return len(p), nil
+	case <-d.done:
+		return 0, io.ErrClosedPipe
+	}
+}
+func (d *testDevice) Close() error { d.once.Do(func() { d.closed.Add(1); close(d.done) }); return nil }
+
+type statusSink struct {
+	mu       sync.Mutex
+	statuses []winn3Status
+}
+
+func (s *statusSink) Write(p []byte) (int, error) {
+	var status winn3Status
+	if err := json.Unmarshal(p, &status); err != nil {
+		return 0, err
+	}
+	s.mu.Lock()
+	s.statuses = append(s.statuses, status)
+	s.mu.Unlock()
+	return len(p), nil
+}
+func (s *statusSink) latest() winn3Status {
+	s.mu.Lock()
+	defer s.mu.Unlock()
+	if len(s.statuses) == 0 {
+		return winn3Status{}
+	}
+	return s.statuses[len(s.statuses)-1]
+}
+func eventually(t *testing.T, what string, fn func() bool) {
+	t.Helper()
+	deadline := time.Now().Add(10 * time.Second)
+	for time.Now().Before(deadline) {
+		if fn() {
+			return
+		}
+		time.Sleep(2 * time.Millisecond)
+	}
+	t.Fatalf("timeout: %s", what)
+}
+
+func TestDirectRuntimeAuthenticatesDeliversAndRevokesPromotion(t *testing.T) {
+	runDirectEndToEnd(t, false)
+}
+
+func TestDirectRuntimeRejectsWrongGatewayAttestation(t *testing.T) {
+	runDirectEndToEnd(t, true)
+}
+
+func runDirectEndToEnd(t *testing.T, wrongAuth bool) {
+	// Only the encrypted outer carrier uses UDP. Both inner devices are direct
+	// in-process calls through the real profile loader, session and tun driver.
+	outer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer outer.Close()
+	path, p, gatewayCfg := profileFixture(t, outer.LocalAddr().String())
+	if wrongAuth {
+		public, _, err := ed25519.GenerateKey(rand.Reader)
+		if err != nil {
+			t.Fatal(err)
+		}
+		if err := securefile.AtomicWrite(p.Keys.DualAuthEd25519PubPath, []byte(hex.EncodeToString(public)), 0600); err != nil {
+			t.Fatal(err)
+		}
+	}
+	classes, err := p.classes()
+	if err != nil {
+		t.Fatal(err)
+	}
+	sizing, err := driver.NewSizing(p.PathMTU, classes...)
+	if err != nil {
+		t.Fatal(err)
+	}
+	var remoteMu sync.Mutex
+	var remote *net.UDPAddr
+	pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: sizing.PathMTU, MaxMessageSize: sizing.MessageSize,
+		Out: func(packet []byte) error {
+			remoteMu.Lock()
+			target := remote
+			remoteMu.Unlock()
+			if target == nil {
+				return errors.New("client has not initiated")
+			}
+			_, err := outer.WriteToUDP(packet, target)
+			return err
+		},
+	})
+	if err != nil {
+		t.Fatal(err)
+	}
+	bridgeDone := make(chan struct{})
+	go func() {
+		defer close(bridgeDone)
+		buf := make([]byte, 65535)
+		for {
+			n, from, err := outer.ReadFromUDP(buf)
+			if err != nil {
+				return
+			}
+			remoteMu.Lock()
+			remote = from
+			remoteMu.Unlock()
+			_ = pipe.Deliver(buf[:n])
+		}
+	}()
+	defer func() { _ = outer.Close(); <-bridgeDone }()
+	gatewayDevice := newTestDevice(sizing.InnerMTU)
+	gateway, err := driver.NewGateway(driver.Config{Session: gatewayCfg, Carrier: pipe, Sizing: sizing,
+		Tun: &tun.Config{Assign: tun.Assignment{V4: netip.MustParseAddr("10.64.0.3"), RouterV4: netip.MustParseAddr("10.64.0.1")}, Device: gatewayDevice,
+			Clock: driver.SessionClock{Clock: driver.SystemClock{}}},
+	})
+	if err != nil {
+		t.Fatal(err)
+	}
+	ctx, cancel := context.WithCancel(t.Context())
+	defer cancel()
+	gatewayDone := make(chan error, 1)
+	go func() { gatewayDone <- gateway.Run(ctx) }()
+	defer func() { cancel(); _ = gatewayDevice.Close(); _ = gateway.Close(); <-gatewayDone }()
+	var native *testDevice
+	r, err := Open(ctx, path, func(mtu int) (Device, error) { native = newTestDevice(mtu); return native, nil })
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer r.Close()
+	sink := &statusSink{}
+	clientDone := make(chan error, 1)
+	go func() { clientDone <- r.Run(ctx, sink) }()
+	defer func() {
+		cancel()
+		select {
+		case <-clientDone:
+		case <-time.After(3 * time.Second):
+			t.Error("client failed to stop")
+		}
+	}()
+	if wrongAuth {
+		eventually(t, "wrong attestation stops client", func() bool { return sink.latest().Event == "stopped" })
+		if s := sink.latest(); s.PromotionReady || s.RxPackets != 0 || s.Posture != "bootstrap" {
+			t.Fatal("wrong gateway attestation permitted promotion")
+		}
+		if r.loop.Carrying() {
+			t.Fatal("wrong gateway attestation left gate carrying")
+		}
+		return
+	}
+	eventually(t, "dual-auth carrying gate", func() bool { return r.loop.Carrying() && gateway.Carrying() })
+	if status := winn3StatusFrom("posture", r.loop, sizing, p.OuterSocketExclusion); status.PromotionReady || status.RxPackets != 0 {
+		t.Fatal("handshake alone promoted")
+	}
+	packet := fixturePacket([4]byte{10, 64, 0, 3}, [4]byte{10, 64, 0, 2})
+	native.reject.Store(true)
+	if err := gateway.SendInner(packet); err != nil {
+		t.Fatal(err)
+	}
+	eventually(t, "failed device write", func() bool { return r.loop.Tunnel().Stats().RxDroppedDevice > 0 })
+	if r.loop.Tunnel().Stats().RxDeviceWrites != 0 {
+		t.Fatal("failed ring write credited as delivered")
+	}
+	if status := winn3StatusFrom("posture", r.loop, sizing, p.OuterSocketExclusion); status.PromotionReady || status.RxPackets != 0 {
+		t.Fatal("failed native write promoted")
+	}
+	native.reject.Store(false)
+	if err := gateway.SendInner(packet); err != nil {
+		t.Fatal(err)
+	}
+	select {
+	case got := <-native.written:
+		if !bytes.Equal(got, packet) {
+			t.Fatal("packet altered")
+		}
+	case <-time.After(3 * time.Second):
+		t.Fatal("no direct delivery")
+	}
+	// The shared tun layer also requires proof that the host device produces
+	// packets. A write alone remains unproven, even with a direct device.
+	if s := winn3StatusFrom("posture", r.loop, sizing, p.OuterSocketExclusion); s.PromotionReady {
+		t.Fatal("unproven host device promoted on a write alone")
+	}
+	native.read <- fixturePacket([4]byte{10, 64, 0, 2}, [4]byte{10, 64, 0, 3})
+	select {
+	case <-gatewayDevice.written:
+	case <-time.After(3 * time.Second):
+		t.Fatal("no encrypted outbound delivery")
+	}
+	eventually(t, "published promotion", func() bool { return sink.latest().PromotionReady })
+	native.read <- fixturePacket([4]byte{192, 0, 2, 9}, [4]byte{10, 64, 0, 3})
+	eventually(t, "spoofed outbound source rejected", func() bool { return r.loop.Tunnel().Stats().TxDroppedInvalid > 0 })
+	cancel()
+	eventually(t, "stopped status", func() bool { return sink.latest().Event == "stopped" })
+	if s := sink.latest(); s.PromotionReady || s.Posture != "bootstrap" {
+		t.Fatal("shutdown retained promotion")
+	}
+	eventually(t, "native close", func() bool { return native.closed.Load() == 1 })
+}
+
+func fixturePacket(src, dst [4]byte) []byte {
+	p := make([]byte, 28)
+	p[0], p[8], p[9] = 0x45, 64, 17
+	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
+	copy(p[12:16], src[:])
+	copy(p[16:20], dst[:])
+	var sum uint32
+	for i := 0; i < 20; i += 2 {
+		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
+	}
+	for sum>>16 != 0 {
+		sum = (sum & 0xffff) + (sum >> 16)
+	}
+	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
+	binary.BigEndian.PutUint16(p[20:22], 40000)
+	binary.BigEndian.PutUint16(p[22:24], 40001)
+	binary.BigEndian.PutUint16(p[24:26], 8)
+	return p
+}
+
+func TestDirectFactoryFailureAndMTUMismatchCloseResources(t *testing.T) {
+	path, _, _ := profileFixture(t, "127.0.0.1:9")
+	for _, kind := range []string{"error", "nil", "mtu", "cancel"} {
+		t.Run(kind, func(t *testing.T) {
+			ctx, cancel := context.WithCancel(t.Context())
+			defer cancel()
+			var native *testDevice
+			r, err := Open(ctx, path, func(mtu int) (Device, error) {
+				if kind == "nil" {
+					return nil, nil
+				}
+				native = newTestDevice(mtu)
+				switch kind {
+				case "error":
+					return native, errors.New("test factory failure")
+				case "mtu":
+					native.mtu++
+				case "cancel":
+					cancel()
+				}
+				return native, nil
+			})
+			if err == nil || r != nil {
+				t.Fatal("invalid factory result accepted")
+			}
+			if native != nil && native.closed.Load() != 1 {
+				t.Fatal("factory resource not closed")
+			}
+		})
+	}
+}
+
+type shortStatusWriter struct{}
+
+func (shortStatusWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
+
+func TestDirectStatusFailureClosesNativeAndCannotRestart(t *testing.T) {
+	path, _, _ := profileFixture(t, "127.0.0.1:9")
+	var native *testDevice
+	r, err := Open(t.Context(), path, func(mtu int) (Device, error) { native = newTestDevice(mtu); return native, nil })
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer r.Close()
+	if err := r.Run(t.Context(), shortStatusWriter{}); !errors.Is(err, io.ErrShortWrite) {
+		t.Fatalf("status error = %v", err)
+	}
+	if native.closed.Load() != 1 {
+		t.Fatal("failed status left native adapter open")
+	}
+	if err := r.Run(t.Context(), io.Discard); err == nil {
+		t.Fatal("closed runtime restarted")
+	}
+}
+
+func TestDirectNativeReadFailureStopsRuntime(t *testing.T) {
+	outer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer outer.Close()
+	path, _, _ := profileFixture(t, outer.LocalAddr().String())
+	var native *testDevice
+	r, err := Open(t.Context(), path, func(mtu int) (Device, error) { native = newTestDevice(mtu); return native, nil })
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer r.Close()
+	sink := &statusSink{}
+	done := make(chan error, 1)
+	go func() { done <- r.Run(t.Context(), sink) }()
+	eventually(t, "initial posture", func() bool { return sink.latest().Event == "posture" })
+	_ = native.Close()
+	select {
+	case err := <-done:
+		if err == nil {
+			t.Fatal("device failure was silent")
+		}
+	case <-time.After(3 * time.Second):
+		t.Fatal("failed device stranded runtime")
+	}
+	if s := sink.latest(); s.Event != "stopped" || s.PromotionReady {
+		t.Fatal("missing stopped status")
+	}
+}
+
+func TestDirectCloseBeforeRunClosesCarrierAndSession(t *testing.T) {
+	path, _, _ := profileFixture(t, "127.0.0.1:9")
+	for _, startupFailure := range []bool{false, true} {
+		r, err := Open(t.Context(), path, func(mtu int) (Device, error) { return newTestDevice(mtu), nil })
+		if err != nil {
+			t.Fatal(err)
+		}
+		if startupFailure {
+			closeUnstartedLoop(r.loop)
+		} else {
+			_ = r.Close()
+		}
+		if !r.loop.Session().State().Terminal() {
+			t.Fatal("unstarted session left live")
+		}
+		if err := r.loop.Carrier().Send(t.Context(), []byte{1}); !errors.Is(err, carrier.ErrClosed) {
+			t.Fatalf("unstarted carrier remained open: %v", err)
+		}
+		_ = r.Close()
+		if err := r.Run(t.Context(), io.Discard); err == nil {
+			t.Fatal("closed runtime restarted")
+		}
+	}
+}
```

### winn_protocol_experimental/winn3/hostqueue/status.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/hostqueue/status.go
@@ -0,0 +1,152 @@
+// SPDX-License-Identifier: MIT
+// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
+// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
+package hostqueue
+
+import (
+	"encoding/json"
+	"fmt"
+	"io"
+
+	"winsvpn.local/winnprotocol/winn3/driver"
+	"winsvpn.local/winnprotocol/winn3/tun"
+)
+
+// PromotionReady shares the desktop predicate. rxPackets must come from the
+// tun layer, which requires both successful writes and a proven device read.
+func PromotionReady(gate tun.State, rxPackets uint64) bool {
+	return gate == tun.StateCarrying && rxPackets > 0
+}
+
+func winn3Posture(ready bool) string {
+	if ready {
+		return winn3PostureFull
+	}
+	return winn3PostureBootstrap
+}
+
+const (
+	winn3PostureBootstrap = "bootstrap"
+
+	winn3PostureFull = "promoted"
+
+	maxWinn3StatusBytes = 64 << 10
+
+	maxWinn3StatusJSONDepth = 8
+)
+
+type winn3Status struct {
+	Event string `json:"event"`
+
+	SessionID string `json:"session_id,omitempty"`
+
+	Posture string `json:"posture"`
+
+	PromotionReady bool `json:"promotion_ready"`
+
+	GateState string `json:"gate_state"`
+
+	RxPackets uint64 `json:"rx_packets"`
+	RxOffered uint64 `json:"rx_offered"`
+
+	TxPackets       uint64 `json:"tx_packets"`
+	TxDroppedClosed uint64 `json:"tx_dropped_closed"`
+	RxDroppedClosed uint64 `json:"rx_dropped_closed"`
+
+	TxDroppedInvalid uint64 `json:"tx_dropped_invalid"`
+
+	MessagesSent     uint64 `json:"messages_sent"`
+	MessagesReceived uint64 `json:"messages_received"`
+	SendFailed       uint64 `json:"send_failed"`
+	RecvFailed       uint64 `json:"recv_failed"`
+	Migrations       uint64 `json:"migrations"`
+
+	Unopenable uint64 `json:"unopenable"`
+
+	PathNarrowedFor uint64 `json:"path_narrowed_for"`
+
+	InnerMTU    int `json:"inner_mtu"`
+	MessageSize int `json:"message_size"`
+
+	InnerIPv6 bool `json:"inner_ipv6"`
+
+	Plan []string `json:"plan"`
+
+	OuterSocketExclusion string `json:"outer_socket_exclusion"`
+
+	Refusal string `json:"refusal,omitempty"`
+}
+
+func winn3StatusFrom(
+	event string,
+	loop *driver.Loop,
+	sizing driver.Sizing,
+	exclusion string,
+) winn3Status {
+	status := winn3Status{
+		Event:                event,
+		InnerMTU:             sizing.InnerMTU,
+		MessageSize:          sizing.MessageSize,
+		InnerIPv6:            sizing.InnerIPv6,
+		OuterSocketExclusion: exclusion,
+	}
+	for _, class := range sizing.Classes {
+		status.Plan = append(status.Plan, class.String())
+	}
+	if loop == nil {
+		status.GateState = tun.StateClosed.String()
+		status.Posture = winn3Posture(false)
+		return status
+	}
+	loopStats := loop.Stats()
+	status.MessagesSent = loopStats.MessagesSent
+	status.MessagesReceived = loopStats.MessagesReceived
+	status.SendFailed = loopStats.SendFailed
+	status.RecvFailed = loopStats.RecvFailed
+	status.Migrations = loopStats.Migrations
+	status.Unopenable = loopStats.Unopenable
+	status.PathNarrowedFor = loopStats.PathNarrowedFor
+
+	tunnel := loop.Tunnel()
+	if tunnel == nil {
+		status.GateState = tun.StateClosed.String()
+		status.Posture = winn3Posture(false)
+		return status
+	}
+	gate := tunnel.Gate().State()
+	tunStats := tunnel.Stats()
+	status.GateState = gate.String()
+	status.RxPackets = tunStats.RxPackets
+	status.RxOffered = tunStats.RxOffered
+	status.TxPackets = tunStats.TxPackets
+	status.TxDroppedClosed = tunStats.TxDroppedClosed
+	status.TxDroppedInvalid = tunStats.TxDroppedInvalid
+	status.RxDroppedClosed = tunStats.RxDroppedClosed
+	status.PromotionReady = PromotionReady(gate, tunStats.RxPackets)
+	status.Posture = winn3Posture(status.PromotionReady)
+	return status
+}
+
+func winn3EncodeStatus(status winn3Status) ([]byte, error) {
+	encoded, err := json.Marshal(status)
+	if err != nil {
+		return nil, fmt.Errorf("encode winn3 status: %w", err)
+	}
+	return encoded, nil
+}
+
+func winn3WriteStatus(w io.Writer, status winn3Status) error {
+	encoded, err := winn3EncodeStatus(status)
+	if err != nil {
+		return err
+	}
+	line := append(encoded, '\n')
+	n, err := w.Write(line)
+	if err != nil {
+		return fmt.Errorf("write winn3 status: %w", err)
+	}
+	if n != len(line) {
+		return io.ErrShortWrite
+	}
+	return nil
+}
```

### winn_protocol_experimental/winn3/session/batch.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/session/batch.go
@@ -0,0 +1,333 @@
+package session
+
+import (
+	"errors"
+	"io"
+	"time"
+
+	"winsvpn.local/winnprotocol/winn3/core"
+)
+
+const MaxBatchSize = core.MaxBatchSize
+
+// ReceiveSlot supplies immutable wire input and distinct plaintext storage.
+// Scratch capacity must cover len(Message)-DemuxTokenSize-AEADTagSize.
+// Packets capacity must be at least len(Message)/3, the maximum TLV count.
+// Returned packets borrow Scratch until it is reused. All buffers must be
+// disjoint across slots, including duplicated input messages and scratch.
+type ReceiveSlot struct {
+	Message []byte
+	Scratch []byte
+	Packets [][]byte
+}
+
+type driverBatch struct {
+	pool     *core.CryptoPool
+	seal     [MaxBatchSize]core.SealSlot
+	open     [MaxBatchSize]core.OpenSlot
+	assembly [MaxBatchSize][]byte
+	counts   [MaxBatchSize]int
+	frames   []core.Frame
+	free     [][]byte
+}
+
+func (d *Driver) batchLocked() *driverBatch {
+	if d.batch == nil {
+		d.batch = &driverBatch{pool: core.NewCryptoPool(), free: make([][]byte, 0, d.cfg.SendQueue)}
+	} else if d.batch.pool == nil {
+		d.batch.pool = core.NewCryptoPool()
+	}
+	return d.batch
+}
+
+// StopCryptoWorkers releases execution resources after a host pump stops.
+// Session keys and protocol state retain their existing Close/Wipe lifecycle.
+// A later explicit batch call may lazily create a new pool. Scalar Poll/Close
+// does not create workers. No worker acquires the driver mutex.
+func (d *Driver) StopCryptoWorkers() {
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	if d.batch != nil {
+		d.batch.pool.Close()
+		d.batch.pool = nil
+	}
+}
+
+func (b *driverBatch) wipe() {
+	for i := range b.assembly {
+		clear(b.assembly[i])
+		b.assembly[i] = nil
+	}
+	clear(b.seal[:])
+	clear(b.open[:])
+	clear(b.counts[:])
+	clear(b.frames)
+	b.frames = nil
+	for i := range b.free {
+		clear(b.free[i])
+		b.free[i] = nil
+	}
+	b.free = nil
+}
+
+// PollBatchInto fills an ordered prefix of at most 32 caller output buffers.
+// Every slot must have capacity MaxMessageSize; short buffers fail before any
+// queue, nonce or accounting mutation. Send the returned prefix in order before
+// polling again, including when err is non-nil. Only the prefix is valid output.
+// Holding d.mu through each worker join makes control hooks hard epoch barriers.
+func (d *Driver) PollBatchInto(slots [][]byte) (int, error) {
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	if len(slots) > MaxBatchSize {
+		return 0, core.ErrBatchSize
+	}
+	if d.state.Terminal() || len(slots) == 0 {
+		return 0, nil
+	}
+	for _, dst := range slots {
+		if cap(dst) < d.cfg.MaxMessageSize {
+			return 0, io.ErrShortBuffer
+		}
+	}
+	n := 0
+	for n < len(slots) && !d.state.Terminal() {
+		now := d.cfg.Clock.Now()
+		if err := d.tick(now); err != nil {
+			return n, err
+		}
+		if d.state.Terminal() {
+			break
+		}
+		if len(d.hsOut) == 0 && len(d.ctrl) == 0 && d.dataMayFlow() && len(d.data) > 0 && d.shape != nil {
+			k, err := d.pollDataBatch(now, slots[n:])
+			n += k
+			if err != nil {
+				return n, err
+			}
+			if k > 0 {
+				continue
+			}
+		}
+		// This path includes every after-hook. Prior parallel work has joined;
+		// the hook's message is fully sealed before the hook installs an epoch.
+		msg, err := d.pollIntoLocked(slots[n])
+		if len(msg) > 0 {
+			slots[n] = slots[n][:len(msg)]
+			copy(slots[n], msg) // also moves handshake output into caller storage
+			n++
+		}
+		if err != nil {
+			return n, err
+		}
+		if len(msg) == 0 {
+			break
+		}
+	}
+	return n, nil
+}
+
+// pollDataBatch prepares only ordinary data. Control messages, including their
+// after-hooks and padding semantics, remain on the shared scalar assembly path.
+func (d *Driver) pollDataBatch(now time.Time, slots [][]byte) (int, error) {
+	b := d.batchLocked()
+	defer func() {
+		for i := range b.assembly {
+			clear(b.assembly[i])
+		}
+		clear(b.seal[:])
+		clear(b.counts[:])
+	}()
+	budget := d.cfg.maxPayload()
+	counter, sent, epochBytes := d.sess.SendCounter(), d.sess.SentBytes(), d.epochBytes
+	n, queued := 0, 0
+	var prepareErr error
+	for n < len(slots) && queued < len(d.data) {
+		// The next Poll must tick before crossing any soft volume boundary.
+		// The first message is allowed: tick has already handled the due policy.
+		if n > 0 && (counter >= d.cfg.RekeyAfterMessages || counter >= core.RekeyAfterMessages || sent >= core.RekeyAfterBytes || epochBytes >= d.cfg.RekeyAfterBytes) {
+			break
+		}
+		if counter >= core.RejectAfterMessages {
+			break
+		}
+		if cap(b.assembly[n]) < budget {
+			b.assembly[n] = make([]byte, budget)
+		}
+		plain := b.assembly[n][:0]
+		k := queued
+		for k < len(d.data) && len(plain)+frameHeaderSize+len(d.data[k]) <= budget {
+			var err error
+			plain, err = core.AppendFrame(plain, core.FrameData, d.data[k])
+			if err != nil {
+				prepareErr = err
+				break
+			}
+			k++
+		}
+		if prepareErr != nil || k == queued {
+			break
+		}
+		target, err := d.shape.target(core.TransportOverhead() + len(plain))
+		if err != nil {
+			prepareErr = err
+			break
+		}
+		b.seal[n] = core.SealSlot{Dst: slots[n], Payload: plain, PadTo: target}
+		b.counts[n] = k - queued
+		queued = k
+		size := uint64(max(target, core.TransportOverhead()+len(plain)))
+		counter++
+		sent += size
+		epochBytes += size
+		n++
+	}
+	if n == 0 {
+		return 0, prepareErr
+	}
+	if err := d.sess.SealBatchInto(b.pool, b.seal[:n]); err != nil {
+		if errors.Is(err, core.ErrCounterExhausted) {
+			d.beginClose(CloseCounterExhausted, err)
+			return 0, nil
+		}
+		return 0, err
+	}
+	for i := 0; i < n; i++ {
+		slots[i] = b.seal[i].Dst
+		d.noteSent(now, len(slots[i]), len(slots[i])-core.TransportOverhead()-len(b.seal[i].Payload))
+		d.stats.DataFramesSent += uint64(b.counts[i])
+	}
+	for i := 0; i < queued; i++ {
+		d.recycleDataBuf(d.data[i])
+	}
+	// Keep the queue's backing slots reusable. Repeated prefix slicing would
+	// allocate a fresh slice backing array on the next Enqueue after a drain.
+	left := copy(d.data, d.data[queued:])
+	clear(d.data[left:])
+	d.data = d.data[:left]
+	return n, prepareErr
+}
+
+// DeliverBatch returns an ordered prefix of ordinary DATA/PAD messages, stopping
+// BEFORE any control message or noise. When the first slot is control, noise or
+// a handshake, it processes exactly that slot and returns one. This lets callers
+// project the gate after each return without calling back while d.mu is held.
+// Unprocessed tickets are canceled without replay commits or byte accounting.
+// Packet views in the processed prefix borrow Scratch until the caller reuses it.
+// Call again on the unprocessed suffix; after terminal state, discard that suffix.
+func (d *Driver) DeliverBatch(slots []ReceiveSlot) (int, error) {
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	if len(slots) > MaxBatchSize {
+		return 0, core.ErrBatchSize
+	}
+	if d.state.Terminal() {
+		return 0, ErrClosed
+	}
+	if len(slots) == 0 {
+		return 0, nil
+	}
+	for i := range slots {
+		x := &slots[i]
+		if cap(x.Scratch) < max(0, len(x.Message)-core.DemuxTokenSize-core.AEADTagSize) || cap(x.Packets) < len(x.Message)/frameHeaderSize {
+			return 0, io.ErrShortBuffer
+		}
+	}
+	for i := range slots {
+		clear(slots[i].Packets)
+		slots[i].Packets = slots[i].Packets[:0]
+	}
+	b := d.batchLocked()
+	defer func() {
+		clear(b.open[:])
+		clear(b.frames)
+		for i := range slots {
+			if len(slots[i].Packets) == 0 {
+				clear(slots[i].Scratch[:cap(slots[i].Scratch)])
+			}
+		}
+	}()
+	// Handshakes may replace sess mid-batch. Tickets are only prepared when a
+	// transport session exists, and are retried by CommitOpen after an epoch cut.
+	prepared := false
+	for i := range slots {
+		if d.state.Terminal() {
+			return i, nil
+		}
+		now := d.cfg.Clock.Now()
+		x := &slots[i]
+		if d.sess == nil {
+			return i + 1, d.deliverHandshake(now, x.Message)
+		}
+		if !prepared {
+			for j := i; j < len(slots); j++ {
+				b.open[j] = core.OpenSlot{Msg: slots[j].Message, Dst: slots[j].Scratch}
+			}
+			if err := d.sess.SpeculateOpenBatch(b.pool, b.open[i:len(slots)]); err != nil {
+				return i, err
+			}
+			prepared = true
+		}
+		plain, err := d.sess.PreviewOpen(&b.open[i])
+		if err != nil {
+			if i > 0 {
+				return i, nil
+			}
+			clear(x.Scratch[:cap(x.Scratch)])
+			return 1, d.deliverUnopenable(now, x.Message)
+		}
+		needed := len(plain) / frameHeaderSize
+		if cap(b.frames) < needed {
+			b.frames = make([]core.Frame, needed)
+		} else {
+			b.frames = b.frames[:needed]
+		}
+		frames, parseErr := core.ParseFramesInto(b.frames[:0], plain)
+		control := parseErr != nil
+		for _, f := range frames {
+			if f.Type != core.FrameData && f.Type != core.FramePad {
+				control = true
+				break
+			}
+		}
+		if control && i > 0 {
+			return i, nil
+		}
+		if _, err := d.sess.CommitOpen(&b.open[i]); err != nil {
+			return i + 1, d.deliverUnopenable(now, x.Message)
+		}
+		d.lastOpened = now
+		d.rekeyConfirmAt = time.Time{}
+		d.stats.MessagesReceived++
+		d.stats.BytesReceived += uint64(len(x.Message))
+		if parseErr != nil {
+			d.beginClose(CloseProtocolError, wrap(ErrProtocol, "peer sent an unparseable frame stream: %v", parseErr))
+			return i + 1, nil
+		}
+		x.Packets, err = d.handleFramesInto(now, frames, len(x.Message) >= d.cfg.MaxMessageSize, x.Packets, true)
+		clear(b.frames)
+		if err != nil {
+			return i + 1, err
+		}
+		if control {
+			return i + 1, nil
+		}
+	}
+	return len(slots), nil
+}
+
+// deliverUnopenable is shared with scalar Deliver to preserve reinitiation,
+// throttling and silent-noise semantics after speculative failures.
+func (d *Driver) deliverUnopenable(now time.Time, msg []byte) error {
+	if d.role == core.RoleResponder && d.resp != nil && !now.Before(d.reinitAt) {
+		d.reinitAt = now.Add(reinitCheckInterval)
+		adopted, authenticated, err := d.admitReinitiation(now, msg)
+		if err != nil {
+			return err
+		}
+		if adopted || authenticated {
+			return nil
+		}
+	}
+	d.stats.Unopenable++
+	return nil
+}
```

### winn_protocol_experimental/winn3/session/batch_lifecycle_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/session/batch_lifecycle_test.go
@@ -0,0 +1,41 @@
+package session
+
+import (
+	"errors"
+	"testing"
+
+	"winsvpn.local/winnprotocol/winn3/core"
+)
+
+func TestStage5StopWorkersPreservesSessionAndRetiresPool(t *testing.T) {
+	p := stage5Pair(t)
+	if err := p.cli.Enqueue([]byte("first")); err != nil {
+		t.Fatal(err)
+	}
+	out := stage5Output(p.cli, 1)
+	if n, err := p.cli.PollBatchInto(out); n != 1 || err != nil {
+		t.Fatalf("first batch: %d %v", n, err)
+	}
+	old := p.cli.batch.pool
+	counter, epoch := p.cli.sess.SendCounter(), p.cli.Epoch()
+	p.cli.StopCryptoWorkers()
+	p.cli.StopCryptoWorkers()
+	if p.cli.batch.pool != nil || p.cli.State() != StateEstablished || p.cli.Epoch() != epoch {
+		t.Fatal("worker retirement changed protocol state or retained workers")
+	}
+	if err := p.cli.sess.SealBatchInto(old, []core.SealSlot{{Dst: out[0], Payload: []byte("stale")}}); !errors.Is(err, core.ErrPoolClosed) {
+		t.Fatalf("retired pool accepted work: %v", err)
+	}
+	if p.cli.sess.SendCounter() != counter {
+		t.Fatal("retired work consumed a nonce")
+	}
+	if err := p.cli.Enqueue([]byte("second")); err != nil {
+		t.Fatal(err)
+	}
+	if n, err := p.cli.PollBatchInto(out); n != 1 || err != nil {
+		t.Fatalf("resumed batch: %d %v", n, err)
+	}
+	if p.cli.batch.pool == old || p.cli.sess.SendCounter() != counter+1 {
+		t.Fatal("batch restart reused a closed pool or reset its nonce")
+	}
+}
```

### winn_protocol_experimental/winn3/session/batch_test.go

<!-- winn345-patch:diff -->
```diff
--- /dev/null
+++ b/winn_protocol_experimental/winn3/session/batch_test.go
@@ -0,0 +1,336 @@
+package session
+
+import (
+	"bytes"
+	"errors"
+	"io"
+	"runtime"
+	"testing"
+
+	"winsvpn.local/winnprotocol/winn3/core"
+)
+
+func stage5Pair(t *testing.T) *pair {
+	p := newPair(t, func(a, z *Config) { a.Padding = core.PadNone; z.Padding = core.PadNone })
+	p.establish()
+	t.Cleanup(func() {
+		p.cli.mu.Lock()
+		p.cli.terminate()
+		p.cli.mu.Unlock()
+		p.gw.mu.Lock()
+		p.gw.terminate()
+		p.gw.mu.Unlock()
+	})
+	return p
+}
+
+func stage5Output(d *Driver, n int) [][]byte {
+	x := make([][]byte, n)
+	for i := range x {
+		x[i] = make([]byte, 0, d.cfg.MaxMessageSize)
+	}
+	return x
+}
+
+func stage5Input(msgs ...[]byte) []ReceiveSlot {
+	x := make([]ReceiveSlot, len(msgs))
+	for i, msg := range msgs {
+		x[i] = ReceiveSlot{Message: msg, Scratch: bytes.Repeat([]byte{0xa5}, len(msg)), Packets: make([][]byte, 0, len(msg)/frameHeaderSize)}
+	}
+	return x
+}
+
+func stage5Message(t *testing.T, d *Driver, typ core.FrameType, data []byte) []byte {
+	t.Helper()
+	f, err := core.AppendFrame(nil, typ, data)
+	if err != nil {
+		t.Fatal(err)
+	}
+	m, err := d.sess.Seal(f, 0)
+	if err != nil {
+		t.Fatal(err)
+	}
+	return m
+}
+
+func TestStage5DriverBatchDataOrderAccountingAndAliases(t *testing.T) {
+	p := stage5Pair(t)
+	beforeTx, beforeRx := p.cli.Stats(), p.gw.Stats()
+	const count = 16
+	for i := 0; i < count; i++ {
+		if err := p.cli.Enqueue(bytes.Repeat([]byte{byte(i)}, p.cli.cfg.maxPayload()-frameHeaderSize)); err != nil {
+			t.Fatal(err)
+		}
+	}
+	out := stage5Output(p.cli, count)
+	backing := make([]*byte, count)
+	for i := range out {
+		backing[i] = &out[i][:cap(out[i])][0]
+	}
+	n, err := p.cli.PollBatchInto(out)
+	if err != nil || n != count {
+		t.Fatalf("poll %d: %v", n, err)
+	}
+	var size uint64
+	for i := range out {
+		if &out[i][0] != backing[i] {
+			t.Fatal("output slot lost its backing storage")
+		}
+		size += uint64(len(out[i]))
+	}
+	in := stage5Input(out...)
+	n, err = p.gw.DeliverBatch(in)
+	if err != nil || n != count {
+		t.Fatalf("deliver %d: %v", n, err)
+	}
+	for i := range in {
+		if len(in[i].Packets) != 1 || !bytes.Equal(in[i].Packets[0], bytes.Repeat([]byte{byte(i)}, p.cli.cfg.maxPayload()-frameHeaderSize)) {
+			t.Fatalf("packet order %d", i)
+		}
+		if &in[i].Packets[0][0] != &in[i].Scratch[2+frameHeaderSize] {
+			t.Fatal("packet was allocated instead of borrowing scratch")
+		}
+		if cap(in[i].Packets[0]) != len(in[i].Packets[0]) {
+			t.Fatal("packet exposes adjacent frame capacity")
+		}
+	}
+	a, z := p.cli.Stats(), p.gw.Stats()
+	if a.BytesSent-beforeTx.BytesSent != size || z.BytesReceived-beforeRx.BytesReceived != size || a.DataFramesSent-beforeTx.DataFramesSent != count || z.DataFramesReceived-beforeRx.DataFramesReceived != count {
+		t.Fatal("batch accounting differs from wire bytes")
+	}
+	if p.cli.batch.pool == nil || p.gw.batch.pool == nil {
+		t.Fatal("batch worker pool absent")
+	}
+}
+
+func TestStage5DriverDataCloseDataBoundaryAndWipe(t *testing.T) {
+	p := stage5Pair(t)
+	in := stage5Input(stage5Message(t, p.cli, core.FrameData, []byte("before")), stage5Message(t, p.cli, core.FrameClose, []byte{byte(CloseNormal)}), stage5Message(t, p.cli, core.FrameData, []byte("after")))
+	before := p.gw.Stats()
+	n, err := p.gw.DeliverBatch(in)
+	if err != nil || n != 1 || p.gw.State() != StateEstablished || string(in[0].Packets[0]) != "before" {
+		t.Fatalf("DATA prefix %d: %v state %s", n, err, p.gw.State())
+	}
+	if p.gw.Stats().MessagesReceived-before.MessagesReceived != 1 {
+		t.Fatal("unreturned control committed early")
+	}
+	n, err = p.gw.DeliverBatch(in[1:])
+	if err != nil || n != 1 || p.gw.State() != StateClosed {
+		t.Fatalf("CLOSE boundary %d: %v", n, err)
+	}
+	if len(in[2].Packets) != 0 || !bytes.Equal(in[2].Scratch, make([]byte, len(in[2].Scratch))) {
+		t.Fatal("canceled post-close plaintext retained")
+	}
+	if string(in[0].Packets[0]) != "before" {
+		t.Fatal("close erased already returned packet view")
+	}
+	if p.gw.Stats().MessagesReceived-before.MessagesReceived != 2 {
+		t.Fatal("post-close ticket committed")
+	}
+	if p.gw.batch.frames != nil || p.gw.batch.assembly[0] != nil {
+		t.Fatal("terminate retained batch storage")
+	}
+	if _, err := p.gw.sess.Open(in[2].Message); err != core.ErrWiped {
+		t.Fatal("session not wiped", err)
+	}
+	if _, err := p.gw.DeliverBatch(in[2:]); err != ErrClosed {
+		t.Fatal(err)
+	}
+}
+
+func TestStage5DriverBatchNoiseAndDuplicateBoundaries(t *testing.T) {
+	p := stage5Pair(t)
+	real := stage5Message(t, p.cli, core.FrameData, []byte("real"))
+	bad := bytes.Clone(real)
+	bad[len(bad)-1] ^= 1
+	in := stage5Input(bad, real, bytes.Clone(real))
+	before := p.gw.Stats()
+	n, err := p.gw.DeliverBatch(in)
+	if err != nil || n != 1 || len(in[0].Packets) != 0 {
+		t.Fatalf("corrupt boundary %d %v", n, err)
+	}
+	n, err = p.gw.DeliverBatch(in[1:])
+	if err != nil || n != 1 || string(in[1].Packets[0]) != "real" {
+		t.Fatalf("genuine boundary %d %v", n, err)
+	}
+	n, err = p.gw.DeliverBatch(in[2:])
+	if err != nil || n != 1 || len(in[2].Packets) != 0 {
+		t.Fatalf("duplicate boundary %d %v", n, err)
+	}
+	after := p.gw.Stats()
+	if after.Unopenable-before.Unopenable != 2 || after.MessagesReceived-before.MessagesReceived != 1 || after.BytesReceived-before.BytesReceived != uint64(len(real)) {
+		t.Fatal("duplicate/corrupt accounting")
+	}
+}
+
+func TestStage5DriverBatchShortBuffersDoNotConsume(t *testing.T) {
+	p := stage5Pair(t)
+	if err := p.cli.Enqueue([]byte("queued")); err != nil {
+		t.Fatal(err)
+	}
+	before := p.cli.sess.SendCounter()
+	out := stage5Output(p.cli, 2)
+	out[1] = make([]byte, 1)
+	if n, err := p.cli.PollBatchInto(out); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
+		t.Fatalf("short poll %d: %v", n, err)
+	}
+	if p.cli.sess.SendCounter() != before || len(p.cli.data) != 1 {
+		t.Fatal("short output consumed queue or nonce")
+	}
+	msg := stage5Message(t, p.cli, core.FrameData, []byte("real"))
+	in := stage5Input(msg)
+	in[0].Packets = nil
+	if n, err := p.gw.DeliverBatch(in); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
+		t.Fatalf("short refs %d: %v", n, err)
+	}
+	in = stage5Input(msg)
+	if n, err := p.gw.DeliverBatch(in); n != 1 || err != nil || len(in[0].Packets) != 1 {
+		t.Fatalf("retry %d: %v", n, err)
+	}
+}
+
+func TestStage5DriverBatchRekeyACKOldEpochAndNewProbe(t *testing.T) {
+	p := stage5Pair(t)
+	epoch := p.cli.Epoch()
+	if err := p.cli.startRekey(p.clk.Now()); err != nil {
+		t.Fatal(err)
+	}
+	init := stage5Output(p.cli, 4)
+	n, err := p.cli.PollBatchInto(init)
+	if err != nil || n != 1 {
+		t.Fatalf("init %d: %v", n, err)
+	}
+	if n, err := p.gw.DeliverBatch(stage5Input(init[0])); n != 1 || err != nil {
+		t.Fatalf("init delivery %d: %v", n, err)
+	}
+	ack := stage5Output(p.gw, 4)
+	n, err = p.gw.PollBatchInto(ack)
+	if err != nil || n != 1 || p.gw.Epoch() != epoch+1 || p.cli.Epoch() != epoch {
+		t.Fatalf("ack %d: %v", n, err)
+	}
+	if n, err := p.cli.DeliverBatch(stage5Input(ack[0])); n != 1 || err != nil || p.cli.Epoch() != epoch+1 {
+		t.Fatalf("ACK was not sealed with old epoch: %d %v", n, err)
+	}
+	probe := stage5Output(p.cli, 4)
+	n, err = p.cli.PollBatchInto(probe)
+	if err != nil || n == 0 {
+		t.Fatalf("new probe %d: %v", n, err)
+	}
+	for i := 0; i < n; i++ {
+		if _, err := p.gw.DeliverBatch(stage5Input(probe[i])); err != nil {
+			t.Fatal(err)
+		}
+	}
+	if p.gw.DataPlaneState() != StateEstablished {
+		t.Fatal("new-epoch probe did not release ACK confirmation hold")
+	}
+}
+
+func TestStage5DriverBatchVolumeBoundary(t *testing.T) {
+	for _, byBytes := range []bool{false, true} {
+		name := "messages"
+		if byBytes {
+			name = "bytes"
+		}
+		t.Run(name, func(t *testing.T) {
+			p := stage5Pair(t)
+			if byBytes {
+				p.cli.cfg.RekeyAfterBytes = p.cli.epochBytes + uint64(2*p.cli.cfg.MaxMessageSize)
+			} else {
+				p.cli.cfg.RekeyAfterMessages = p.cli.sess.SendCounter() + 2
+			}
+			for i := 0; i < 5; i++ {
+				if err := p.cli.Enqueue(make([]byte, p.cli.cfg.maxPayload()-frameHeaderSize)); err != nil {
+					t.Fatal(err)
+				}
+			}
+			out := stage5Output(p.cli, 8)
+			n, err := p.cli.PollBatchInto(out)
+			if err != nil || n != 3 || p.cli.State() != StateRekeying {
+				t.Fatalf("volume cut n=%d state=%s err=%v", n, p.cli.State(), err)
+			}
+			if len(p.cli.data) != 3 {
+				t.Fatal("data crossed rekey volume barrier")
+			}
+		})
+	}
+}
+
+func TestStage5DriverBatchReceiveNoHotAllocation(t *testing.T) {
+	p := stage5Pair(t)
+	p.cli.cfg.RekeyAfterBytes = ^uint64(0)
+	p.cli.cfg.RekeyAfterMessages = ^uint64(0)
+	payload, err := core.AppendFrame(nil, core.FrameData, bytes.Repeat([]byte{5}, 1200))
+	if err != nil {
+		t.Fatal(err)
+	}
+	msg := make([]byte, 1500)
+	in := stage5Input(msg)
+	allocs := testing.AllocsPerRun(50, func() {
+		m, err := p.cli.sess.SealInto(msg, payload, 0)
+		if err != nil {
+			panic(err)
+		}
+		in[0].Message = m
+		if n, err := p.gw.DeliverBatch(in); err != nil || n != 1 {
+			panic("batch failed")
+		}
+	})
+	if allocs != 0 {
+		t.Fatalf("receive hot path allocated %.2f times", allocs)
+	}
+	runtime.KeepAlive(in)
+}
+
+func TestStage5DriverBatchSendNoHotAllocation(t *testing.T) {
+	p := stage5Pair(t)
+	out := stage5Output(p.cli, 8)
+	payload := bytes.Repeat([]byte{5}, p.cli.cfg.maxPayload()-frameHeaderSize)
+	// Warm the worker count under AllocsPerRun's GOMAXPROCS=1, the queue,
+	// assembly slots, and packet freelist before measuring steady state.
+	allocs := testing.AllocsPerRun(50, func() {
+		for range out {
+			if err := p.cli.Enqueue(payload); err != nil {
+				panic(err)
+			}
+		}
+		if n, err := p.cli.PollBatchInto(out); err != nil || n != len(out) {
+			panic("send batch failed")
+		}
+	})
+	if allocs != 0 {
+		t.Fatalf("send hot path allocated %.2f times", allocs)
+	}
+}
+
+func TestStage5DriverAfterHookOrdersEpochOutput(t *testing.T) {
+	p := stage5Pair(t)
+	secret := bytes.Repeat([]byte{0x63}, 32)
+	epoch := p.cli.Epoch()
+	p.cli.ctrl = append(p.cli.ctrl, pendingFrame{typ: core.FramePad, wide: true}, pendingFrame{typ: core.FramePad, after: func() error {
+		if err := p.cli.sess.Rekey(secret); err != nil {
+			return err
+		}
+		p.cli.ctrl = append(p.cli.ctrl, padFrame())
+		return nil
+	}})
+	out := stage5Output(p.cli, 4)
+	n, err := p.cli.PollBatchInto(out)
+	if err != nil || n != 3 || p.cli.Epoch() != epoch+1 {
+		t.Fatalf("epoch output %d: %v", n, err)
+	}
+	for i := 0; i < 2; i++ {
+		if _, err := p.gw.sess.Open(out[i]); err != nil {
+			t.Fatalf("old output %d was reordered across install: %v", i, err)
+		}
+	}
+	if _, err := p.gw.sess.Open(out[2]); err == nil {
+		t.Fatal("new output sealed under old epoch")
+	}
+	if err := p.gw.sess.Rekey(secret); err != nil {
+		t.Fatal(err)
+	}
+	if _, err := p.gw.sess.Open(out[2]); err != nil {
+		t.Fatal("new output not recoverable after install", err)
+	}
+}
```

### winn_protocol_experimental/winn3/session/driver.go

<!-- winn345-patch:diff -->
```diff
--- a/winn_protocol_experimental/winn3/session/driver.go
+++ b/winn_protocol_experimental/winn3/session/driver.go
@@ -134,7 +134,7 @@
 }
 
 // Driver is the frame-level session driver: one logical Winn3 session, with no
-// socket, no timer and no goroutine of its own.
+// socket or timer. Batch APIs lazily start a bounded crypto worker pool.
 //
 // Enqueue, Poll and Deliver are safe to call concurrently.
 type Driver struct {
@@ -142,7 +142,8 @@
 	cfg      Config
 	role     core.Role
 
-	mu sync.Mutex
+	mu    sync.Mutex
+	batch *driverBatch
 
 	state       State
 	failed      error
@@ -669,6 +670,19 @@
 }
 
 func (d *Driver) getDataBuf(size int) []byte {
+	if d.batch != nil {
+		for i := len(d.batch.free) - 1; i >= 0; i-- {
+			b := d.batch.free[i]
+			if cap(b) < size {
+				continue
+			}
+			last := len(d.batch.free) - 1
+			d.batch.free[i] = d.batch.free[last]
+			d.batch.free[last] = nil
+			d.batch.free = d.batch.free[:last]
+			return b[:size]
+		}
+	}
 	if size <= 2048 {
 		bp := dataBufPool.Get().(*[]byte)
 		return (*bp)[:size]
@@ -677,10 +691,16 @@
 }
 
 func (d *Driver) recycleDataBuf(b []byte) {
+	if d.batch != nil && len(d.batch.free) < cap(d.batch.free) {
+		b = b[:cap(b)]
+		clear(b)
+		d.batch.free = append(d.batch.free, b)
+		return
+	}
 	if cap(b) >= 2048 {
-		b = b[:2048]
-		clear(b)
-		dataBufPool.Put(&b)
+		pooled := b[:2048]
+		clear(pooled)
+		dataBufPool.Put(&pooled)
 	}
 }
 
@@ -759,6 +779,10 @@
 func (d *Driver) PollInto(dst []byte) ([]byte, error) {
 	d.mu.Lock()
 	defer d.mu.Unlock()
+	return d.pollIntoLocked(dst)
+}
+
+func (d *Driver) pollIntoLocked(dst []byte) ([]byte, error) {
 	if d.state.Terminal() {
 		return nil, nil
 	}
@@ -871,18 +895,7 @@
 		// one attempt per reinitCheckInterval happens, and a client that is
 		// genuinely reconnecting retransmits its initiation on its own Retry
 		// schedule, which lands it inside a later window.
-		if d.role == core.RoleResponder && d.resp != nil && !now.Before(d.reinitAt) {
-			d.reinitAt = now.Add(reinitCheckInterval)
-			adopted, authenticated, err := d.admitReinitiation(now, msg)
-			if err != nil {
-				return nil, err
-			}
-			if adopted || authenticated {
-				return nil, nil
-			}
-		}
-		d.stats.Unopenable++
-		return nil, nil
+		return nil, d.deliverUnopenable(now, msg)
 	}
 	d.lastOpened = now
 	// Anything that opens here was sealed under a key the peer could only
@@ -1943,7 +1956,12 @@
 // --- inbound frames ---------------------------------------------------------
 
 func (d *Driver) handleFrames(now time.Time, frames []core.Frame, wide bool) ([][]byte, error) {
-	var out [][]byte
+	return d.handleFramesInto(now, frames, wide, nil, false)
+}
+
+// borrow is used only with batch-owned plaintext and prevalidated output
+// capacity. Scalar callers retain their independently owned packet copies.
+func (d *Driver) handleFramesInto(now time.Time, frames []core.Frame, wide bool, out [][]byte, borrow bool) ([][]byte, error) {
 	for _, f := range frames {
 		switch f.Type {
 		case core.FrameData:
@@ -1951,8 +1969,11 @@
 				d.stats.DataFramesDropped++
 				continue
 			}
-			p := make([]byte, len(f.Value))
-			copy(p, f.Value)
+			p := f.Value
+			if !borrow {
+				p = make([]byte, len(f.Value))
+				copy(p, f.Value)
+			}
 			out = append(out, p)
 			d.stats.DataFramesReceived++
 
@@ -2414,6 +2435,11 @@
 }
 
 func (d *Driver) terminate() {
+	// Batch workers never acquire d.mu. Batch APIs join before frame handlers
+	// or after-hooks run, so termination cannot wait on itself here.
+	if d.batch != nil {
+		d.batch.pool.Close()
+	}
 	if d.failed != nil {
 		d.state = StateFailed
 	} else {
@@ -2454,6 +2480,9 @@
 		d.ini.Wipe()
 		d.ini = nil
 	}
+	if d.batch != nil {
+		d.batch.wipe()
+	}
 }
 
 // LocalCloseReason reports the reason this end closed with, or zero.
```

## Execution provenance

Six Cursor/Grok 4.6 Extra High lane requests were attempted and all returned usage-exhausted errors before work. The built-in collaboration spawn failed because this CLI thread was unavailable to that service. Six bounded Astra CLI fallback processes then ran carrier, Apple, Android, Windows, crypto and independent review lanes. Their live PIDs and tool events were checked. Main retained loop integration, independent reruns, corrections, source/patch verification and final conclusions. No inactive or rejected lane is counted as successful work.

