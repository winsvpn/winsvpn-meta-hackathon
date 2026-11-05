# Winn Protocol v3 Stages 3, 4, 5 Systems Engineering Study: 5.6 Sol

- **Model**: `gpt-5.6-sol` (extra high reasoning)
- **Completed**: 2026-09-14 07:53:25 UTC
- **Exit code**: 0
- **Wall clock limit**: 21600s (timed out: False)

## Deep Study Report & Implementation Plan

# Winn Protocol v3 Stages 3, 4, and 5 systems engineering study

Date: 2026-09-14  
Workspace: `/Users/owner/.gemini/antigravity/scratch/winn3_speed_lanes/sol`  
Scope: Stage 3 socket lifetime and UDP batching, Stage 4 native host bridges, Stage 5 ordered multicore transport crypto  
Disposition: architecture approved for an implementation branch, release status remains NO-GO until the gates in section 12 pass

## 1. Executive verdict

The requested direction is sound, but the safe implementation boundary is larger than the file list in the request.

1. Stage 3 can use one optional datagram batch contract without widening the four-method `carrier.Carrier` interface. Linux can use real `recvmmsg` and `sendmmsg` through `x/net`. Android needs a reviewed raw syscall backend or a small maintained fork because `x/net` selects its one-message fallback when `runtime.GOOS == "android"`. Darwin also gets one message per `ReadBatch` or `WriteBatch` call. Apple throughput therefore comes from the NetworkExtension array boundary and the batch C ABI, not from a claimed Darwin `recvmmsg` path.
2. `UDP_SEGMENT` and `UDP_GRO` are Linux-only, capability-probed optimizations. GSO may combine only an ordered run of independently sealed, equal-length Winn datagrams for the same peer. GRO must be split from its ancillary segment-size record before token lookup or AEAD. The aggregate IPv4 UDP payload is capped at 65,507 bytes, the segment count is capped at 64, and every split datagram remains an independently authenticated Winn message.
3. Socket cancellation belongs to a carrier generation. The current packet path creates a channel and a `context.AfterFunc` callback on every send and receive at `winn_protocol_experimental/winn3/carrier/udp.go:521-557`. One generation callback can interrupt both directions and remove that repeated allocation. A generation number is required so an old callback cannot poison a reused socket after migration.
4. Apple already receives packet arrays from `NEPacketTunnelFlow.readPackets`, then throws the batching away by calling the C ABI once per packet at `apple/WinsTunnelCore/WinsWinn3Datapath.swift:342-394`. The reverse pump takes one packet and invokes `writePackets` with one-element arrays at `:396-462`. A descriptor-array ABI is the correct fix.
5. Android's current hot path is a `FileInputStream` reader, a per-packet `ByteArray.copyOf`, an `ArrayBlockingQueue<ByteArray>`, a second copy on dequeue, and one framed local-socket message per packet at `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:33-57,129-180` and `WinnV3Bridge.kt:183-271`. The lowest-risk first implementation is a fixed reusable slot ring plus versioned batch frames. Direct TUN descriptor ownership is the final shape, but it also requires a second descriptor handoff, child-side Android TUN adoption, descriptor replacement control, and explicit ownership on close.
6. Windows cannot remove the loopback relay by changing `windows/winn3_engine/relay.go` and `main_windows.go` alone. That process owns Wintun while a separate `winn-datapath.exe` owns the protocol. The direct design puts the Wintun backend inside `cmd/winn-datapath`, adds a `wintun` device kind, and changes `windows/runner/winn3_supervisor.*` to launch one process. Wintun's receive and send rings then connect directly to `driver.Loop`.
7. Stage 5 cannot safely wrap worker goroutines around the current `session.Driver`. `PollInto` and `Deliver` hold one driver mutex across protocol state and AEAD work at `winn_protocol_experimental/winn3/session/driver.go:759-780,842-920`. Core `SealInto` and `OpenInto` also hold direction mutexes across ChaCha20-Poly1305 at `winn_protocol_experimental/winn3/core/session.go:342-390,415-488`. The required change is a two-phase core API: sequential reserve, parallel crypto, sequential ordered commit.
8. Rekey is an admission barrier, not merely a worker-pool drain. Existing `after` hooks install the new epoch immediately after building the control ciphertext at `winn_protocol_experimental/winn3/session/driver.go:1870-1898,2317-2345`. With workers, that hook may run only after every earlier old-epoch job is complete and the last old-epoch ciphertext is in the ordered carrier queue.

No source file outside this report was changed by this study.

## 2. Evidence and provenance

### 2.1 Source identity

The workspace contains `.git/HEAD`, `.git/config`, and `.git/index`, but it has no usable object or reference database. Both `git status` and `git rev-parse HEAD` fail with `fatal: not a git repository`. A commit SHA and a trustworthy dirty-tree statement therefore cannot be produced. That is a release-provenance blocker.

The exact reviewed file bytes are identified below so the study remains reproducible:

| File | SHA-256 |
|---|---|
| `winn_protocol_experimental/go.mod` | `4c273ecd3464e8dfe4778eb569169cbc640d294de42b32359428c8ca8f1bb1e9` |
| `winn_protocol_experimental/go.sum` | `20e36d1a8c735ad1a7e8526a117f6e5c59c7d4e75c0ae2d01448c0e026a020e2` |
| `winn_protocol_experimental/winn3/carrier/carrier.go` | `76cf6ea2ef9e9e8e34c38597291f7ca17ccb140917eac535f11280880cc14b03` |
| `winn_protocol_experimental/winn3/carrier/udp.go` | `a7084b29c09d1ac2154368b7b45c611dbf28236e7321594892ed75edaa010dc3` |
| `winn_protocol_experimental/winn3/driver/loop.go` | `0f61ceebe96c1ce61d202c71af62a902a284e108934fbb0f700a235f6328e212` |
| `winn_protocol_experimental/winn3/session/driver.go` | `3c54db024746c263b1d67fc922b30a197fbafe1b8bcbfb90f749dab738ecdeef` |
| `winn_protocol_experimental/winn3/core/session.go` | `5a68b704195f8cee3df755fe1c4980157ead92e9f08e2e4d11ad567f56eb036d` |
| `winn_protocol_experimental/cdatapath/winn_datapath_winn3.go` | `6d59ea3b301cb983c3dbaa4106edb7a643e87bc12c29598bfab015ea5e0c1228` |
| `winn_protocol_experimental/cdatapath/winn_datapath.h` | `9d9453c11126365770a4ae45149ea4da1242859abb19e81cc15f2a0aeb328e86` |
| `apple/WinsTunnelCore/WinsWinn3Datapath.swift` | `53dbf01ce92a579c5452934bba51fd94e4a22f47756c26378c4b8eccf2d3fe03` |
| `apple/EngineWrappers/WinnTunnel.h` | `16759ca0287dc32867fb2ea26a0602c951ed184b773b47c4eae7ebbf674ca6bd` |
| `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt` | `1585ea9647527ea6787fc3678f29d5f74cee41e737fb62cc71d15e64e57d75c0` |
| `android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt` | `4847f9677d4fbebb483a48a22089e095b8d9a9f782748789df15ab983b9f3595` |
| `windows/winn3_engine/relay.go` | `ec17fb8c2217fc2f3c99850ef4c097153d8749e30f0c26fee4e181ea89030545` |
| `windows/winn3_engine/main_windows.go` | `9b5a10d5a30466a5ec0ffd2c5ee00dc6e0b24abe959030d2a7a94194d50255a4` |

These full hashes identify the local files, but they are not substitutes for a commit. Before implementation, regenerate them in a complete clone and bind them to the revision:

```sh
git rev-parse HEAD
git status --short
shasum -a 256 \
  winn_protocol_experimental/winn3/carrier/carrier.go \
  winn_protocol_experimental/winn3/carrier/udp.go \
  winn_protocol_experimental/winn3/driver/loop.go \
  winn_protocol_experimental/winn3/session/driver.go \
  winn_protocol_experimental/winn3/core/session.go \
  winn_protocol_experimental/cdatapath/winn_datapath_winn3.go \
  apple/WinsTunnelCore/WinsWinn3Datapath.swift \
  android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt \
  android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt \
  windows/winn3_engine/relay.go \
  windows/winn3_engine/main_windows.go
```

### 2.2 Fresh verification

Command run from `winn_protocol_experimental`:

```sh
go test -race ./winn3/...
```

Result on 2026-09-14:

- PASS: `agent`, `carrier`, `conform`, `core`, `core/replaystore`, `driver`, `driver/dpbridge`, `dualsign`, `gateway`, `netlab`, `session`, and `tun`.
- FAIL: `winn3/redteam`.
- The first redteam failure is a missing generated `build/redteam_verdicts.txt` artifact.
- Its binary tests then fail before execution because Go VCS stamping cannot read the incomplete `.git` metadata. The emitted guidance is `Use -buildvcs=false to disable VCS stamping.`

This is not a clean global race result. It is also not evidence of a data race in the packages that passed. Generate the redteam artifact in a complete clone and rerun without disabling VCS evidence for a release candidate.

An explicit second command naming every non-redteam package passed under `-race`. This avoided `go list`, which also tries to obtain the unavailable VCS status in this workspace. The passing package set was `agent`, `agent/trace`, `carrier`, `conform`, `core`, `core/replaystore`, `driver`, `driver/dpbridge`, `dualsign`, `gateway`, `netlab`, `session`, and `tun`.

The exact Phase 1 and Phase 2 numbers in the mission statement are treated as owner-supplied accepted input. A fresh subset was run and is reported in section 10.1: it reproduced zero allocations, 11.71 to 12.44 Mpps for cached demux, and up to 529.86 MB/s for the 1400-byte round trip. The source still has a lifetime-byte issue that Stage 5 must correct: `core.Session.NeedsRekey` tests lifetime `sentBytes` at `winn_protocol_experimental/winn3/core/session.go:309-323`, while `session.Driver` separately resets `epochBytes` after PQ and ordinary rekey at `winn_protocol_experimental/winn3/session/driver.go:2196,2370`. Parallel reservation must use one epoch-local byte authority.

### 2.3 Primary external contracts

- [`x/net/ipv4.PacketConn.ReadBatch`](https://pkg.go.dev/golang.org/x/net/ipv4#PacketConn.ReadBatch) documents optimized batching on Linux and one message on other platforms. The reviewed v0.56.0 source switches specifically on `runtime.GOOS == "linux"`, so Android takes the scalar branch.
- [`udp(7)`](https://man7.org/linux/man-pages/man7/udp.7.html) documents Linux 4.18 `UDP_SEGMENT`, the 64-datagram call limit, per-send control messages, and Linux 5.0 `UDP_GRO` with a segment-size control message.
- [Linux segmentation offload documentation](https://docs.kernel.org/networking/segmentation-offloads.html) defines GSO and GRO roles in the kernel path.
- [Apple `readPackets`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets%28completionhandler%3A%29) returns packet arrays and requires another read request after the completion.
- [Apple `writePackets`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets%28_%3Awithprotocols%3A%29) accepts packet and protocol arrays whose counts must match.
- [Android `VpnService.Builder.establish`](https://developer.android.com/reference/kotlin/android/net/VpnService.Builder#establish()) states that the returned descriptor is nonblocking by default, that each read retrieves an outgoing packet, each write injects one, and `ParcelFileDescriptor.detachFd()` is the path for complete native ownership.
- [Wintun's official API example](https://git.zx2c4.com/wintun/tree/README.md?h=0.11) requires `ReceivePacket` followed by `ReleaseReceivePacket`, and `AllocateSendPacket` followed by `SendPacket`. Allocation order defines send order.
- [Go `runtime.GOMAXPROCS`](https://pkg.go.dev/runtime#GOMAXPROCS) is the current bound on CPUs executing Go code simultaneously. It can change automatically on current Go when no explicit setting disables updates, so worker count is captured once at pool construction and published in status.

## 3. Current path and exact bottleneck evidence

### 3.1 UDP and driver

`carrier.Carrier` is intentionally scalar at `winn_protocol_experimental/winn3/carrier/carrier.go:13-34`. Preserve it for TCP and TLS migration compatibility. Add batching as optional interfaces.

`UDP.Send` arms a per-call cancellation callback and performs one `Write` or `WriteToUDP` at `winn_protocol_experimental/winn3/carrier/udp.go:363-414`. `RecvInto` performs one `ReadFromUDPAddrPort` at `:425-499`. `armRead` and `armWrite` allocate a channel plus callback state at `:521-557`.

`driver.Loop.drain` polls one ciphertext and sends one message at `winn_protocol_experimental/winn3/driver/loop.go:526-563`. `readLoop` owns one 65,535-byte buffer, receives one message, calls one `Deliver`, and writes each inner packet separately at `:594-671`.

### 3.2 Apple

The Swift wrapper already has a packet-array source, but its loop makes one C call per element. The inverse pump allocates one data buffer, takes one C result, and calls `writePackets` with arrays of length one. See `apple/WinsTunnelCore/WinsWinn3Datapath.swift:342-462`.

The Go `abiDevice` uses pointer-rich `[][]byte` queues at `winn_protocol_experimental/cdatapath/winn_datapath_winn3.go:244-267`. `WritePacket`, `offer`, and `take` copy one packet per operation at `:315-400`. A batch ABI without replacing those queues only moves foreign-call cost. It does not remove the Go queue allocations.

### 3.3 Android

`WinnV3AndroidTunDevice` owns Java streams at `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:33-57`. The adapter reader allocates `buffer.copyOf(n)` and enqueues the new array at `:145-166`; dequeue copies it again at `:174-180`. The bridge creates one frame for every packet in both directions at `android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt:183-271`.

There is a stale, security-significant comment conflict. The active standalone frame server says Inbound frames are inner IP packets at `winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go:28-46,488-499`, and Android `VpnTunnelService.kt:2516,2654-2660` selects `payload:"ip-packet"`. In contrast, `android/app/src/main/kotlin/org/winsvpn/app/WinnProtocolFraming.kt:45-64` and `WinnEngineTransport.kt` still describe the frame payload as AmneziaWG outer datagrams. Correct those comments and add a contract test before changing packet ownership.

### 3.4 Windows

`pumpTunToSeam` releases a borrowed Wintun packet only after writing it to loopback UDP at `windows/winn3_engine/relay.go:73-104`. `pumpSeamToTun` receives into a reusable buffer, validates, allocates a Wintun send-ring packet, and copies at `:112-148` and `windows/winn3_engine/main_windows.go:523-536`.

`main_windows.go:243-356` binds the seam, reports a host port, waits for the protocol engine's port, opens Wintun, then runs two pumps. `windows/runner/winn3_supervisor.cpp:298-303` resolves two executables. Direct memory handoff requires one executable or shared memory. A Go channel cannot cross this process boundary.

### 3.5 Crypto

`session.Driver` advertises concurrent safety but implements it with one mutex at `winn_protocol_experimental/winn3/session/driver.go:136-146`. `PollInto` holds it across time transitions, frame assembly, and Seal at `:759-780,1777-1898`. `Deliver` holds it across Open, replay mutation, parsing, and control state at `:842-920`.

Core `Session` has direction mutexes and a ratchet lock at `winn_protocol_experimental/winn3/core/session.go:79-122`. `SealInto` assigns the counter, computes the token, encrypts, and increments accounting under `sendMu` at `:342-390`. `OpenInto` resolves and consumes replay under `recvMu` at `:415-488`. These critical sections are the Stage 5 serialization point.

## 4. Stage 3 architecture

### 4.1 Optional carrier contract

The exact public contract is:

```go
// File: winn_protocol_experimental/winn3/carrier/batch.go
package carrier

import (
    "context"
    "net"
)

const (
    DefaultRecvBatch = 16
    DefaultSendBatch = 32
    MaxBatchMessages = 64
)

// BatchMsg is caller-owned descriptor storage. Buffers and OOB storage are
// installed once and reused. RecvBatch writes Addr, Flags, N, and NN.
type BatchMsg struct {
    Buffers [][]byte
    OOB    []byte
    Addr   net.Addr
    N      int
    NN     int
    Flags  int
}

// BatchCarrier is optional. A successful count is always a prefix. A method
// may return n > 0 with a non-nil error. It never returns 0, nil.
type BatchCarrier interface {
    RecvBatch(ctx context.Context, msgs []BatchMsg) (n int, err error)
    SendBatch(ctx context.Context, msgs []BatchMsg) (n int, err error)
}

// LifetimeBinder binds blocking socket interruption to one carrier generation.
// Rebinding invalidates the older generation callback before clearing deadlines.
type LifetimeBinder interface {
    BindLifetime(ctx context.Context) error
}
```

Why `Buffers [][]byte`, not one `[]byte`: it maps without payload copies onto `ipv4.Message` and `ipv6.Message`, and it permits a future header plus payload vectored send. Descriptor initialization may allocate during loop construction. The steady packet path performs only field assignments.

Contract rules:

1. Empty descriptor arrays and arrays longer than 64 return `ErrConfig`.
2. Receive descriptors must have at least one byte buffer with aggregate capacity at least 65,535 bytes when GRO is disabled. GRO uses an aggregate buffer capped by the IP-family UDP ceiling.
3. Send validates every packet before issuing the syscall. A zero or oversize message rejects the whole batch without a partial send.
4. `n` is a committed prefix. Callers retain the exact ciphertext bytes for `[n:]`.
5. `MSG_TRUNC` or `MSG_CTRUNC` rejects that descriptor. No truncated bytes reach token lookup.
6. Explicit-peer filtering happens per descriptor. Foreign messages update only `Foreign`, then accepted descriptors are compacted by swapping descriptors, not copying packet bytes.
7. A capability error can permanently select scalar fallback for that direction. `EAGAIN`, `ENOBUFS`, `EINTR`, route errors, and context cancellation are not capability failures.
8. The driver discovers optional interfaces once per carrier generation and records batch capability in status.

### 4.2 OS backend matrix

| Target | Receive | Send | Status |
|---|---|---|---|
| Linux | `x/net` `ReadBatch`, real `recvmmsg` | `x/net` `WriteBatch`, real `sendmmsg` | implement first |
| Android | in-repo connected-UDP raw `recvmmsg` | in-repo connected-UDP raw `sendmmsg` | implement after Linux, prove on USB device |
| macOS and iOS | `x/net` one-message compatibility path | `x/net` one-message compatibility path | correct fallback, not a syscall win |
| Windows | scalar UDP carrier if used | scalar UDP carrier if used | Stage 4 removes the inner loopback path |

The Android raw backend should accept connected UDP only. The host already creates and protects the outer socket. Connecting it before SCM_RIGHTS transfer moves peer filtering into the kernel and avoids handwritten `sockaddr` marshalling in the syscall backend. If the socket is unconnected, use scalar `net.UDPConn` until a reviewed address-marshalling implementation exists.

### 4.3 Driver ownership

```text
TUN read owner
    -> session sequencer reserves and builds up to 32 ciphertext slots
    -> pending ordered ciphertext prefix
    -> SendBatch
    -> release only the committed prefix

RecvBatch into 16 fixed slots
    -> split GRO aggregate into independent descriptors
    -> session Deliver or Stage 5 verify queue, in descriptor order
    -> batched native TUN egress
```

`Loop` needs a fixed outbound slot array and a pending range. Polling a message consumes a nonce and session queue state, so a partial send may not call `PollInto` again for that packet. It retries the same bytes:

```go
type pendingCipherBatch struct {
    msgs  [carrier.DefaultSendBatch]carrier.BatchMsg
    bufs  [carrier.DefaultSendBatch][]byte
    first int
    count int
}

func (p *pendingCipherBatch) advance(n int) {
    p.first += n
    p.count -= n
    if p.count == 0 {
        p.first = 0
    }
}
```

The buffers are allocated once at `newLoop` with `Sizing.MessageSize` capacity. `drain` first sends any pending suffix. Only an empty pending range may call `PollInto` and reuse slots. Migration transfers this pending byte ownership to the new carrier because sizing is already based on the carrier floor.

### 4.4 Generation lifetime cancellation

Use one callback per `BindLifetime`, never one per datagram:

```go
// Fields added to carrier.UDP.
lifeMu   sync.Mutex
lifeGen  uint64
lifeDone <-chan struct{}
lifeStop func() bool

func (u *UDP) BindLifetime(ctx context.Context) error {
    if ctx == nil {
        return wrap(ErrConfig, "nil lifetime context")
    }
    u.lifeMu.Lock()
    if u.lifeStop != nil {
        u.lifeStop()
    }
    u.lifeGen++
    generation := u.lifeGen
    u.lifeDone = ctx.Done()
    readDeadline, hasDeadline := ctx.Deadline()
    if !hasDeadline {
        readDeadline = time.Time{}
    }
    if err := u.conn.SetDeadline(readDeadline); err != nil {
        u.lifeMu.Unlock()
        return err
    }
    u.lifeStop = context.AfterFunc(ctx, func() {
        u.lifeMu.Lock()
        current := generation == u.lifeGen
        u.lifeMu.Unlock()
        if current {
            _ = u.conn.SetDeadline(aLongTimeAgo)
        }
    })
    u.lifeMu.Unlock()
    return nil
}

func (u *UDP) usesLifetime(ctx context.Context) bool {
    if ctx == nil || ctx.Done() == nil {
        return false
    }
    u.lifeMu.Lock()
    same := ctx.Done() == u.lifeDone
    u.lifeMu.Unlock()
    return same
}
```

`armRead` and `armWrite` return a package-level no-op when `usesLifetime(ctx)` is true. They keep the existing slow deadline path for an unrelated bounded context such as close drain. `Loop.Run` and `Loop.Migrate` call `BindLifetime` before publishing the new carrier generation. `UDP.Close` increments `lifeGen` and stops the callback before closing an owned socket.

The callback checks the generation again after acquiring `lifeMu`. This is what prevents an old canceled context from setting a past deadline after a new generation cleared it.

### 4.5 GSO and GRO

GSO is an ordered coalescing transform over ciphertext, not a transport format change.

Eligibility for one `UDP_SEGMENT` send:

```text
run length >= 2
all destinations equal
all segment lengths equal
segment length <= active carrier ceiling
run length <= 64
segment length * run length <= family UDP payload ceiling
no control or address change between descriptors
```

For IPv4, the aggregate payload ceiling is `65535 - 20 - 8 = 65507`. For ordinary IPv6 UDP without jumbograms it is `65535 - 8 = 65527`. Continue to enforce the smaller active path ceiling on each Winn datagram. Set `UDP_SEGMENT` as a per-`sendmsg` control message, not a socket-wide default, because adjacent padding buckets can have different segment sizes.

Enable GRO only after OOB storage and parsing are active. `UDP_GRO` may return several UDP datagrams as one buffer and a native-endian `uint16` segment size. Split before demux:

```go
func splitGRO(total, segment int, emit func(offset, length int) error) error {
    if total <= 0 || segment <= 0 || segment > total {
        return errors.New("invalid UDP_GRO segment size")
    }
    for offset := 0; offset < total; offset += segment {
        length := segment
        if remaining := total - offset; remaining < length {
            length = remaining
        }
        if err := emit(offset, length); err != nil {
            return err
        }
    }
    return nil
}
```

The final segment may be shorter. Every segment receives its own arrival sequence. Each is checked against the Winn message floor and active message ceiling. A malformed or truncated ancillary record drops the entire aggregate and increments a named `gro_malformed` counter.

Capability policy:

- At socket creation, try `setsockopt(SOL_UDP, UDP_GRO, 1)` only when configured.
- A probe failure disables GRO and records the errno. It does not fail the tunnel.
- GSO is attempted only for eligible runs. `ENOPROTOOPT`, `EOPNOTSUPP`, and `EINVAL` from a known-valid probe permanently disable it for that socket generation.
- Any fallback sends the same independent ciphertext descriptors with `sendmmsg`. It does not reseal.
- Packet capture must prove datagram count, lengths, order, and bytes are identical with offload on and off.

## 5. Stage 3 reference diff and implementation manifest

The following is the reviewed patch surface and reference implementation. It is intentionally split so each commit has an independently testable invariant. Section 14 records why it is not a certified cross-platform patch bundle.

### S3.1: contract and portable x/net adapter

```diff
diff --git a/winn_protocol_experimental/winn3/carrier/carrier.go b/winn_protocol_experimental/winn3/carrier/carrier.go
--- a/winn_protocol_experimental/winn3/carrier/carrier.go
+++ b/winn_protocol_experimental/winn3/carrier/carrier.go
@@
 type Carrier interface {
@@
 }
+
+const (
+    DefaultRecvBatch = 16
+    DefaultSendBatch = 32
+    MaxBatchMessages = 64
+)
+
+type BatchMsg struct {
+    Buffers [][]byte
+    OOB    []byte
+    Addr   net.Addr
+    N      int
+    NN     int
+    Flags  int
+}
+
+type BatchCarrier interface {
+    RecvBatch(context.Context, []BatchMsg) (int, error)
+    SendBatch(context.Context, []BatchMsg) (int, error)
+}
+
+type LifetimeBinder interface {
+    BindLifetime(context.Context) error
+}
```

`carrier.go` already imports `context` and `net`, so this hunk adds no import.

Add `winn_protocol_experimental/winn3/carrier/udp_batch.go`:

```go
package carrier

import (
    "context"
    "errors"
    "io"
    "net"
    "syscall"

    "golang.org/x/net/ipv4"
    "golang.org/x/net/ipv6"
)

type udpBatchConn interface {
    ReadBatch([]ipv4.Message, int) (int, error)
    WriteBatch([]ipv4.Message, int) (int, error)
}

type udp4BatchConn struct{ conn *ipv4.PacketConn }

func (c udp4BatchConn) ReadBatch(msgs []ipv4.Message, flags int) (int, error) {
    return c.conn.ReadBatch(msgs, flags)
}

func (c udp4BatchConn) WriteBatch(msgs []ipv4.Message, flags int) (int, error) {
    return c.conn.WriteBatch(msgs, flags)
}

type udp6BatchConn struct{ conn *ipv6.PacketConn }

func (c udp6BatchConn) ReadBatch(msgs []ipv4.Message, flags int) (int, error) {
    return c.conn.ReadBatch(msgs, flags)
}

func (c udp6BatchConn) WriteBatch(msgs []ipv4.Message, flags int) (int, error) {
    return c.conn.WriteBatch(msgs, flags)
}

func newUDPBatchConn(conn *net.UDPConn, peer *net.UDPAddr) udpBatchConn {
    address := peer
    if remote, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
        address = remote
    }
    if address == nil {
        address, _ = conn.LocalAddr().(*net.UDPAddr)
    }
    if address != nil && address.IP != nil && address.IP.To4() == nil {
        return udp6BatchConn{conn: ipv6.NewPacketConn(conn)}
    }
    return udp4BatchConn{conn: ipv4.NewPacketConn(conn)}
}

func validateBatch(msgs []BatchMsg) error {
    if len(msgs) == 0 || len(msgs) > MaxBatchMessages {
        return wrap(ErrConfig, "batch length %d, want 1..%d", len(msgs), MaxBatchMessages)
    }
    return nil
}

func buffersLen(buffers [][]byte) int {
    total := 0
    for _, buffer := range buffers {
        total += len(buffer)
    }
    return total
}

func (u *UDP) RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
    if err := validateBatch(msgs); err != nil {
        return 0, err
    }
    if err := ctx.Err(); err != nil {
        return 0, err
    }
    for i := range msgs {
        if buffersLen(msgs[i].Buffers) < maxRecvDatagram {
            return 0, io.ErrShortBuffer
        }
    }

    u.recvMu.Lock()
    defer u.recvMu.Unlock()
    stop := u.armRead(ctx)
    defer stop()

    for {
        u.mu.Lock()
        closed, ceiling, peer := u.closed, u.maxMessage, u.peer
        u.mu.Unlock()
        if closed {
            return 0, ErrClosed
        }

        native := u.batchRead[:len(msgs)]
        for i := range native {
            native[i].Buffers = msgs[i].Buffers
            native[i].OOB = msgs[i].OOB
            native[i].Addr = nil
            native[i].N = 0
            native[i].NN = 0
            native[i].Flags = 0
        }
        count, readErr := u.batch.ReadBatch(native, 0)
        if count < 0 || count > len(native) {
            return 0, errors.New("winn3/carrier: invalid batch read count")
        }

        accepted := 0
        foreign := uint64(0)
        rejected := uint64(0)
        bytes := uint64(0)
        for i := 0; i < count; i++ {
            message := native[i]
            if message.Flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 ||
                message.N <= 0 || message.N > ceiling {
                rejected++
                continue
            }
            if peer != nil {
                from, ok := message.Addr.(*net.UDPAddr)
                if !ok || !sameUDPAddr(peer, from) {
                    foreign++
                    continue
                }
            }
            msgs[accepted] = msgs[i]
            msgs[accepted].Addr = message.Addr
            msgs[accepted].N = message.N
            msgs[accepted].NN = message.NN
            msgs[accepted].Flags = message.Flags
            bytes += uint64(message.N)
            accepted++
        }

        u.mu.Lock()
        u.stats.Foreign += foreign
        u.stats.RecvErrors += rejected
        if accepted > 0 {
            u.stats.Delivered += uint64(accepted)
            u.stats.DeliveredBytes += bytes
            u.stats.LastDelivered = u.clock.Now()
        } else if readErr != nil {
            u.stats.RecvErrors++
        }
        u.mu.Unlock()

        if accepted > 0 || readErr != nil {
            return accepted, readErr
        }
    }
}

func (u *UDP) SendBatch(ctx context.Context, msgs []BatchMsg) (int, error) {
    if err := validateBatch(msgs); err != nil {
        return 0, err
    }
    if err := ctx.Err(); err != nil {
        return 0, err
    }
    u.mu.Lock()
    closed, ceiling, peer := u.closed, u.maxMessage, u.peer
    u.mu.Unlock()
    if closed {
        return 0, ErrClosed
    }
    for i := range msgs {
        size := buffersLen(msgs[i].Buffers)
        if size == 0 {
            return 0, ErrMessageEmpty
        }
        if size > ceiling {
            return 0, wrap(ErrMessageTooLarge, "%d bytes, ceiling %d", size, ceiling)
        }
    }

    u.sendMu.Lock()
    defer u.sendMu.Unlock()
    stop := u.armWrite(ctx)
    defer stop()

    native := u.batchWrite[:len(msgs)]
    for i := range native {
        native[i].Buffers = msgs[i].Buffers
        native[i].OOB = msgs[i].OOB
        native[i].Addr = peer
        native[i].N = 0
        native[i].NN = 0
        native[i].Flags = 0
    }
    count, err := u.batch.WriteBatch(native, 0)
    if count < 0 || count > len(native) {
        return 0, errors.New("winn3/carrier: invalid batch write count")
    }
    sentBytes := uint64(0)
    for i := 0; i < count; i++ {
        sentBytes += uint64(buffersLen(msgs[i].Buffers))
    }
    u.mu.Lock()
    u.stats.Sent += uint64(count)
    u.stats.SentBytes += sentBytes
    if count > 0 {
        u.stats.LastSend = u.clock.Now()
    }
    if err != nil {
        u.stats.SendErrors++
    }
    u.mu.Unlock()
    return count, err
}

var _ BatchCarrier = (*UDP)(nil)
```

Required `UDP` field and constructor diff:

```diff
diff --git a/winn_protocol_experimental/winn3/carrier/udp.go b/winn_protocol_experimental/winn3/carrier/udp.go
--- a/winn_protocol_experimental/winn3/carrier/udp.go
+++ b/winn_protocol_experimental/winn3/carrier/udp.go
@@
 type UDP struct {
     conn *net.UDPConn
+    batch udpBatchConn
@@
     recvMu sync.Mutex
+    sendMu sync.Mutex
     buf    []byte
+    batchRead  [MaxBatchMessages]ipv4.Message
+    batchWrite [MaxBatchMessages]ipv4.Message
@@
 }
@@
-    return &UDP{
+    result := &UDP{
         conn:                  cfg.Conn,
@@
-    }, nil
+    }
+    result.batch = newUDPBatchConn(cfg.Conn, cfg.Peer)
+    return result, nil
```

Add `"golang.org/x/net/ipv4"` to `udp.go` imports. Lock `sendMu` around the existing scalar socket write so scalar and batch calls cannot reorder. The full driver patch must precede performance claims because the interface alone changes no syscall count.

### S3.2: driver batch ownership

The implementation commit changes these exact functions:

- `newLoop`: allocate 32 outbound slot buffers and 16 inbound slot buffers once.
- `Run` and `Migrate`: call `LifetimeBinder.BindLifetime` before publishing a generation.
- `drain`: fill only empty pending slots, then call `SendBatch`; preserve a partial suffix byte-for-byte.
- `readLoop`: call `RecvBatch` and deliver every successful descriptor prefix in array order.
- `drainQueuedClose`: drain existing pending ciphertext before asking the session for another message.

Do not make `maxDrainPerWake` the batch size. It is a fairness bound. One wake can perform several batches until that bound is reached.

### S3.3: Linux offload

Put all constants and control-message parsing in `winn_protocol_experimental/winn3/carrier/udp_offload_linux.go` with build tag `linux && !android`. Put stubs returning disabled capability in `udp_offload_other.go`. Android gets its own raw mmsg file. This prevents Darwin builds from acquiring Linux constants or unsafe control-message layout.

The Linux implementation must use `unix.SOL_UDP`, `unix.UDP_SEGMENT`, `unix.UDP_GRO`, `unix.ParseSocketControlMessage`, and `encoding/binary.NativeEndian` from the pinned `golang.org/x/sys` version. Preallocate aggregate and OOB buffers on `UDP`. Never allocate them while sending or receiving packets.

## 6. Stage 4 architecture and implementation diffs

### 6.1 Apple: batch the C boundary and the NetworkExtension boundary

The C contract uses one descriptor shape for input and output. Input reads `data` and `length`. Output reads `data` and `capacity`, then writes `length` and `protocol`.

Apply to both `winn_protocol_experimental/cdatapath/winn_datapath.h` and `apple/EngineWrappers/WinnTunnel.h`:

```diff
@@
+typedef struct WinnPacketDescriptor {
+    void *data;
+    int capacity;
+    int length;
+    int protocol;
+} WinnPacketDescriptor;
+
+/*
+ * Returns the committed descriptor prefix or a negative WINN_TUNNEL_ERR code.
+ * Buffers are caller-owned and are not retained. count must be 1 through 64.
+ */
+extern int WinnTunnelWriteInboundBatch(long long handle,
+                                       WinnPacketDescriptor *packets,
+                                       int count);
+
+/*
+ * Blocks for the first packet according to timeoutMS, then drains immediately
+ * available packets. On success it returns 1 through count and fills length and
+ * protocol for that prefix. It never returns zero.
+ */
+extern int WinnTunnelReadOutboundBatch(long long handle,
+                                       WinnPacketDescriptor *packets,
+                                       int count,
+                                       int timeoutMS);
```

Add the same typedef to the cgo preamble in `winn_protocol_experimental/cdatapath/winn_datapath.go`. Export the functions from that file because cgo C types are file-local:

```go
const maxABIPacketBatch = 64

//export WinnTunnelWriteInboundBatch
func WinnTunnelWriteInboundBatch(
    handle C.longlong,
    packets *C.WinnPacketDescriptor,
    count C.int,
) C.int {
    n := int(count)
    if packets == nil || n <= 0 || n > maxABIPacketBatch {
        return errArgument
    }
    descriptors := unsafe.Slice(packets, n)
    if tunnel := lookupWinn3(int64(handle)); tunnel != nil {
        var views [maxABIPacketBatch]abiPacketView
        for i := range descriptors {
            length := int(descriptors[i].length)
            if descriptors[i].data == nil || length <= 0 ||
                int(descriptors[i].capacity) < length {
                return errArgument
            }
            views[i] = abiPacketView{
                bytes: unsafe.Slice((*byte)(descriptors[i].data), length),
            }
        }
        committed, err := tunnel.dev.offerBatch(views[:n])
        if err != nil && committed == 0 {
            if errors.Is(err, winn3DeviceClosed) {
                return errClosed
            }
            return errCarrier
        }
        return C.int(committed)
    }
    engine := lookup(int64(handle))
    if engine == nil {
        return errHandle
    }
    committed := 0
    for i := range descriptors {
        length := int(descriptors[i].length)
        if descriptors[i].data == nil || length <= 0 ||
            int(descriptors[i].capacity) < length {
            if committed > 0 {
                return C.int(committed)
            }
            return errArgument
        }
        packet := unsafe.Slice((*byte)(descriptors[i].data), length)
        if _, err := engine.WriteInbound(packet); err != nil {
            if committed > 0 {
                return C.int(committed)
            }
            return C.int(writeFailureCode(err))
        }
        committed++
    }
    return C.int(committed)
}

//export WinnTunnelReadOutboundBatch
func WinnTunnelReadOutboundBatch(
    handle C.longlong,
    packets *C.WinnPacketDescriptor,
    count C.int,
    timeoutMS C.int,
) C.int {
    n := int(count)
    if packets == nil || n <= 0 || n > maxABIPacketBatch {
        return errArgument
    }
    descriptors := unsafe.Slice(packets, n)
    for i := range descriptors {
        if descriptors[i].data == nil || descriptors[i].capacity <= 0 {
            return errArgument
        }
        descriptors[i].length = 0
        descriptors[i].protocol = 0
    }
    if tunnel := lookupWinn3(int64(handle)); tunnel != nil {
        timeout := deadlineZero
        if timeoutMS > 0 {
            timeout = time.Duration(timeoutMS) * time.Millisecond
        }
        completed := 0
        for i := range descriptors {
            buffer := unsafe.Slice(
                (*byte)(descriptors[i].data), int(descriptors[i].capacity))
            wait := timeout
            if i > 0 {
                wait = time.Nanosecond
            }
            length, err := tunnel.dev.take(buffer, wait)
            if err != nil {
                if completed > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
                    return C.int(completed)
                }
                if completed > 0 {
                    return C.int(completed)
                }
                switch {
                case errors.Is(err, os.ErrDeadlineExceeded):
                    return errTimeout
                case errors.Is(err, errWinn3TooLarge):
                    return errTooLarge
                case errors.Is(err, winn3DeviceClosed):
                    return errClosed
                default:
                    return errCarrier
                }
            }
            descriptors[i].length = C.int(length)
            descriptors[i].protocol = C.int(ipProtocol(buffer[:length]))
            completed++
        }
        return C.int(completed)
    }
    engine := lookup(int64(handle))
    if engine == nil {
        return errHandle
    }
    timeout := deadlineZero
    if timeoutMS > 0 {
        timeout = time.Duration(timeoutMS) * time.Millisecond
    }
    completed := 0
    for i := range descriptors {
        buffer := unsafe.Slice(
            (*byte)(descriptors[i].data), int(descriptors[i].capacity))
        wait := timeout
        if i > 0 {
            wait = time.Nanosecond
        }
        length, err := engine.ReadOutboundTimeout(buffer, wait)
        if err != nil {
            if completed > 0 && errors.Is(err, datapath.ErrDeadlineExceeded) {
                return C.int(completed)
            }
            if completed > 0 {
                return C.int(completed)
            }
            return C.int(readFailureCode(err))
        }
        descriptors[i].length = C.int(length)
        descriptors[i].protocol = C.int(ipProtocol(buffer[:length]))
        completed++
    }
    return C.int(completed)
}

func ipProtocol(packet []byte) int {
    if len(packet) == 0 {
        return 0
    }
    switch packet[0] >> 4 {
    case 4:
        return 2
    case 6:
        return 30
    default:
        return 0
    }
}
```

`2` and `30` are the Darwin address-family values used by `NSNumber(value: AF_INET)` and `NSNumber(value: AF_INET6)`. The Go function should instead use the existing package constants if present, and a test must assert the values on Darwin.

Replace `abiDevice` pointer queues with a fixed ring allocated to the configured inner MTU. The queue operation is one lock acquisition per batch:

```go
type abiPacketView struct {
    bytes []byte
}

type abiSlotRing struct {
    slots   []byte
    lengths []uint16
    stride  int
    head    int
    tail    int
    used    int
}

func newABISlotRing(depth, stride int) abiSlotRing {
    return abiSlotRing{
        slots: make([]byte, depth*stride),
        lengths: make([]uint16, depth),
        stride: stride,
    }
}

func (r *abiSlotRing) push(packet []byte) bool {
    if r.used == len(r.lengths) || len(packet) > r.stride {
        return false
    }
    start := r.tail * r.stride
    copy(r.slots[start:start+len(packet)], packet)
    r.lengths[r.tail] = uint16(len(packet))
    r.tail = (r.tail + 1) % len(r.lengths)
    r.used++
    return true
}

func (r *abiSlotRing) popInto(dst []byte) (int, bool) {
    if r.used == 0 {
        return 0, false
    }
    length := int(r.lengths[r.head])
    if len(dst) < length {
        return length, false
    }
    start := r.head * r.stride
    copy(dst, r.slots[start:start+length])
    clear(r.slots[start : start+length])
    r.lengths[r.head] = 0
    r.head = (r.head + 1) % len(r.lengths)
    r.used--
    return length, true
}
```

For Swift, add the symbols next to the existing scalar type aliases in `apple/WinsTunnelCore/WinsWinn3Datapath.swift`:

```swift
private typealias WriteInboundBatchFn = @convention(c) (
    Int64,
    UnsafeMutablePointer<WinnPacketDescriptor>?,
    Int32
) -> Int32

private typealias ReadOutboundBatchFn = @convention(c) (
    Int64,
    UnsafeMutablePointer<WinnPacketDescriptor>?,
    Int32,
    Int32
) -> Int32

private let writeInboundBatch: WriteInboundBatchFn
private let readOutboundBatch: ReadOutboundBatchFn
private static let packetBatchSize = 32
```

Replace the per-packet host-to-engine loop with one descriptor call. Bridging through `NSData` keeps every pointer alive for the complete foreign call:

```swift
private func enqueueHostBatch(
    _ packets: [Data],
    protocols: [NSNumber],
    handle: Int64
) throws {
    guard packets.count == protocols.count else {
        throw WinsWinn3Error.invalidPacketBatch
    }
    var offset = 0
    while offset < packets.count {
        let end = min(offset + Self.packetBatchSize, packets.count)
        let retained = packets[offset..<end].map { $0 as NSData }
        var descriptors = retained.enumerated().map { index, packet in
            WinnPacketDescriptor(
                data: UnsafeMutableRawPointer(mutating: packet.bytes),
                capacity: Int32(packet.length),
                length: Int32(packet.length),
                protocol: protocols[offset + index].int32Value
            )
        }
        let committed = descriptors.withUnsafeMutableBufferPointer {
            writeInboundBatch(handle, $0.baseAddress, Int32($0.count))
        }
        guard committed == descriptors.count else {
            throw WinsWinn3Error.nativeWrite(Int(committed))
        }
        offset = end
    }
}
```

The outbound pump owns 32 reusable `NSMutableData` slots, calls `readOutboundBatch` once, constructs `Data` values for the successful prefix, then makes exactly one `packetFlow.writePackets(packets, withProtocols: protocols)` call. It may reuse the mutable slots only after `writePackets` returns. Current NetworkExtension documentation gives a synchronous Boolean result, so return is the ownership boundary.

Apple acceptance counters:

- `swift_read_callbacks`
- `swift_packets_from_flow`
- `abi_write_batch_calls`
- `abi_write_packets`
- `abi_read_batch_calls`
- `abi_read_packets`
- `packetflow_write_calls`
- `packetflow_write_packets`

At sustained load, both packets-per-ABI-call ratios and packets-per-`writePackets` ratio must exceed 1.0. A synthetic ABI test alone is not an Apple extension proof.

### 6.2 Android: fixed slots and versioned packet batches

Direct descriptor ownership is the best final datapath, but the current route-promotion design replaces the Android TUN descriptor while preserving the v3 session. The existing per-generation reader is what prevents a blocked read on the deactivated descriptor from pinning the whole tunnel at `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:59-103,234-249`. Removing it without a native descriptor-rebind protocol is a correctness regression.

The first safe implementation keeps one reader per descriptor generation, but replaces the allocating queue and per-packet framed IPC:

1. Allocate 256 fixed packet slots once at the current inner MTU.
2. Read directly into a free slot.
3. Publish the slot index through a bounded primitive ring.
4. Drain up to 32 slots into one batch frame.
5. Return slots only after the framed write completes.
6. Decode one outbound batch and issue packet writes in order to the current device.
7. Preserve generation abandonment and bounded drop accounting.

Add `android/app/src/main/kotlin/org/winsvpn/app/WinnPacketBatch.kt`:

```kotlin
package org.winsvpn.app

internal object WinnPacketBatch {
    const val MAX_PACKETS = 32
    private const val COUNT_BYTES = 2
    private const val LENGTH_BYTES = 2

    data class View(val offset: Int, val length: Int)

    fun encodeInto(
        destination: ByteArray,
        packets: Array<ByteArray>,
        lengths: IntArray,
        count: Int,
    ): Int {
        require(count in 1..minOf(MAX_PACKETS, packets.size, lengths.size))
        var required = COUNT_BYTES
        for (index in 0 until count) {
            val length = lengths[index]
            require(length in 1..minOf(0xffff, packets[index].size))
            required += LENGTH_BYTES + length
        }
        require(required <= destination.size)
        putU16(destination, 0, count)
        var cursor = COUNT_BYTES
        for (index in 0 until count) {
            val length = lengths[index]
            putU16(destination, cursor, length)
            cursor += LENGTH_BYTES
            System.arraycopy(packets[index], 0, destination, cursor, length)
            cursor += length
        }
        return cursor
    }

    fun decode(payload: ByteArray): List<View> {
        require(payload.size >= COUNT_BYTES)
        val count = getU16(payload, 0)
        require(count in 1..MAX_PACKETS)
        val result = ArrayList<View>(count)
        var cursor = COUNT_BYTES
        repeat(count) {
            require(cursor + LENGTH_BYTES <= payload.size)
            val length = getU16(payload, cursor)
            cursor += LENGTH_BYTES
            require(length > 0 && cursor + length <= payload.size)
            result.add(View(cursor, length))
            cursor += length
        }
        require(cursor == payload.size)
        return result
    }

    private fun putU16(buffer: ByteArray, offset: Int, value: Int) {
        buffer[offset] = value.toByte()
        buffer[offset + 1] = (value ushr 8).toByte()
    }

    private fun getU16(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xff) or
            ((buffer[offset + 1].toInt() and 0xff) shl 8)
}
```

`decode` allocates views on the control seam. Replace it with `decodeInto(payload, offsets, lengths): Int` for the production hot path. The allocating form is useful only for codec unit tests. Production arrays are created once by the pump.

The framing extension is explicit and must be changed together in:

- `android/app/src/main/kotlin/org/winsvpn/app/WinnProtocolFraming.kt`
- `winn_protocol_experimental/datapath/duplex/duplex.go`
- `windows/runner/winn_frame.h`, which the Android file names as the normative layout
- `winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go`
- interop fixtures and adverse decoder tests

```diff
@@ Android WinnProtocolFraming.kt
     const val OP_INBOUND = 0x0010
     const val OP_OUTBOUND = 0x0011
+    const val OP_INBOUND_BATCH = 0x0012
+    const val OP_OUTBOUND_BATCH = 0x0013
@@
-    fun mustBeNonEmpty(opcode: Int): Boolean = opcode == OP_INBOUND || opcode == OP_OUTBOUND
+    fun mustBeNonEmpty(opcode: Int): Boolean =
+        opcode == OP_INBOUND || opcode == OP_OUTBOUND ||
+            opcode == OP_INBOUND_BATCH || opcode == OP_OUTBOUND_BATCH

@@ Go datapath/duplex
     OpInbound  Opcode = 0x0010
     OpOutbound Opcode = 0x0011
+    OpInboundBatch  Opcode = 0x0012
+    OpOutboundBatch Opcode = 0x0013
```

Do not send either batch opcode until `CreateAck` advertises `packet_batch_v1:true`. An older engine must continue receiving scalar opcodes. An engine that advertises the capability must accept both scalar and batch frames for rollback and mixed bursts.

`WinnEngineTransport.writeFrame` needs an offset and length overload so the batch buffer is not copied:

```kotlin
fun writeFrame(opcode: Int, payload: ByteArray, offset: Int, length: Int)
```

The concrete local-socket transport calls a `WinnFraming.writeFrame` overload that writes the 16-byte header and payload with `android.system.Os.writev` or one reusable fused buffer. `OutputStream.write` of two arrays is two syscalls; `flush` per frame is unnecessary on a local socket with no buffered output wrapper.

Long-term direct ownership:

- Detach the active `ParcelFileDescriptor` only after the Go child is ready to receive ownership.
- Transfer protected UDP and TUN descriptors in one authenticated local-socket startup exchange, with an explicit ordered role table. Descriptor position 0 is UDP, position 1 is TUN.
- Add `winn3_device_tunfd_android.go` to the child and use raw `unix.Read` and `unix.Write` behind one read owner and one write owner.
- Add a separate control socket for a replacement TUN descriptor, or restart the engine with a recorded session-loss consequence. Never send SCM_RIGHTS bytes into the existing framed stream because the ordinary frame reader can consume the associated data byte and desynchronize.
- The native owner closes each adopted descriptor exactly once. Kotlin closes only descriptors it did not transfer.

The direct path is not a two-file Kotlin patch. It changes process startup, descriptor protocol, Go device construction, promotion rebind, and close ownership.

### 6.3 Windows: put Wintun in the protocol process

The target process graph is:

```text
today
Wintun ring <-> winsvpn_winn3_engine.exe <-> loopback UDP <-> winn-datapath.exe

target
Wintun ring <-> winn-datapath.exe driver.Loop <-> protected outer carrier
```

Implement a Windows `tun.Device` in `winn_protocol_experimental/cmd/winn-datapath/winn3_device_wintun_windows.go`. It owns the adapter and session, borrows each receive packet only until it copies into the driver's current buffer, and writes by allocating Wintun send-ring storage. This removes two loopback UDP syscalls, two scheduler/process crossings, peer-pin work, and an intermediate receive buffer per packet. A later borrowed-slot driver API can remove the remaining Wintun-to-driver copy.

Required repository changes:

1. Add `golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2` to `winn_protocol_experimental/go.mod`, matching `windows/winn3_engine/go.mod`.
2. Add profile device kind `wintun` and require `device.name` while forbidding `host_port`.
3. Add the Windows device file and a non-Windows refusal stub.
4. Make `winn3BuildDevice` construct it only after the protected outer carrier is ready.
5. Publish adapter name, LUID, MTU, ring capacity, and readiness through the existing status/control channel.
6. Change `windows/runner/winn3_supervisor.*` to launch only `winn-datapath.exe`, wait for adapter readiness, install bootstrap posture, then apply the existing promotion predicate.
7. Stop packaging `winsvpn_winn3_engine.exe` for v3 after rollback and upgrade tests pass.
8. Delete `windows/winn3_engine/relay.go` and `main_windows.go` only in the cleanup commit. Keeping dead relay code during the transition provides rollback and makes review of topology changes possible.

Core device methods are:

```go
func (d *winn3WintunDevice) ReadPacket(dst []byte) (int, error) {
    for {
        if d.stopping.Load() {
            return 0, net.ErrClosed
        }
        packet, err := d.session.ReceivePacket()
        if err == nil {
            if len(packet) > len(dst) {
                d.session.ReleaseReceivePacket(packet)
                return 0, io.ErrShortBuffer
            }
            n := copy(dst, packet)
            d.session.ReleaseReceivePacket(packet)
            return n, nil
        }
        if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
            return 0, err
        }
        if err := d.waitReadable(); err != nil {
            return 0, err
        }
    }
}

func (d *winn3WintunDevice) WritePacket(packet []byte) (int, error) {
    if d.stopping.Load() {
        return 0, net.ErrClosed
    }
    target, err := d.session.AllocateSendPacket(len(packet))
    if err != nil {
        if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
            return 0, fmt.Errorf("%w: wintun send ring full", tun.ErrDeviceWrite)
        }
        return 0, fmt.Errorf("%w: %v", tun.ErrDeviceWrite, err)
    }
    copy(target, packet)
    d.session.SendPacket(target)
    return len(packet), nil
}
```

Shutdown order is a hard invariant:

1. Set `stopping`.
2. Signal the manual-reset quit event.
3. Wait until the driver read and write owners have returned from all Wintun calls.
4. Call `session.End()` once.
5. Close the adapter once.
6. Close event handles.

The existing `main_windows.go:291-302,323-356,385-460` commentary already explains why ending the Wintun session before pumps exit is unsafe. Preserve that logic when ownership moves.

Windows source currently labels hardware execution as unverified at `windows/winn3_engine/main_windows.go:80-111`. Cross-compilation is not runtime proof. Promotion requires a physical Windows run with route, DNS, IPv6, stop, and leak evidence.

## 7. Stage 5 ordered multicore architecture

### 7.1 State ownership

One session sequencer remains the sole writer of:

- protocol state and timers
- frame assembly order
- outbound sequence number
- nonce counter reservation
- epoch-local message and byte budgets
- inbound arrival sequence
- replay commit
- DATA delivery order
- control-frame effects
- rekey admission barriers

Workers own only:

- one ChaCha20-Poly1305 send object and one receive object for one immutable epoch
- nonce scratch private to that worker
- a job slot while computing Seal or Open
- no socket, no replay window, no protocol state, and no ratchet authority

This matches the useful part of wireguard-go's execution shape: sequential nonce assignment, parallel cryptography, sequential transmission. Winn adds arrival-ordered replay commit because its token lookup and control-frame state machine are not WireGuard's queue model.

### 7.2 Outbound ticket lifecycle

```text
assemble ordered frame plaintext
    -> decide exact padding and wire length
    -> reserve epoch, counter, token, nonce, and wire-byte charge
    -> dispatch immutable Seal ticket
    -> worker writes ciphertext into owned slot
    -> completion ring marks sequence ready
    -> ordered emitter appends exact ciphertext to carrier pending queue
    -> ordered emitter runs ticket hooks
    -> carrier commits a successful prefix
    -> release committed slots
```

Rules:

1. Reservation increments the counter and epoch byte total before dispatch.
2. Capacity, payload length, padding target, and state gate are validated before reservation.
3. Worker failure does not roll back a counter.
4. Send failure does not recreate a ticket. The exact ciphertext stays pending.
5. Later completions cannot pass a missing earlier sequence.
6. A control ticket whose hook changes epoch sets `barrierAfter`. No later old-epoch ticket is admitted.
7. The hook runs only after its ciphertext is present in the ordered carrier queue and both old-epoch worker directions are drained.

### 7.3 Inbound ticket lifecycle

```text
RecvBatch descriptor order
    -> assign arrival sequence
    -> resolve token to counter without consuming replay
    -> dispatch immutable Open ticket
    -> worker authenticates and decrypts into owned slot
    -> completion ring marks sequence ready
    -> ordered commit rechecks epoch and replay window
    -> consume replay only after AEAD success
    -> parse frames and mutate protocol state in arrival order
    -> deliver DATA in arrival order
```

Do not reserve the replay counter before AEAD. An attacker could send a corrupted copy first and suppress the later genuine copy. Multiple copies can perform crypto concurrently. Ordered commit accepts the first authentic copy whose counter is still live; failures consume nothing, and later valid duplicates fail the commit recheck after one copy succeeds.

### 7.4 Worker count and queues

At pool construction:

```go
workers := runtime.GOMAXPROCS(0)
if configured > 0 {
    workers = min(configured, workers)
}
if workers < 1 {
    workers = 1
}
```

The automatic default is exactly the captured `GOMAXPROCS(0)` bound requested for this stage. Publish both the captured bound and active worker count. Do not resize a live epoch pool when the Go runtime later adjusts its default. Re-evaluate at the next epoch barrier or session start.

Use bounded queues:

- outbound slots: 256 per client session for initial tuning
- inbound slots: 256 per client session
- carrier send batch: 32
- carrier receive batch: 16
- maximum worker count: captured `GOMAXPROCS(0)`

The gateway must not allocate 512 maximum-size slots per session. It uses shared per-worker arenas plus small bounded per-session descriptor rings. Account memory as `slot_count * slot_stride`, publish it, and set a global cap.

### 7.5 Rekey barrier

A strict barrier is:

1. Mark the session as stopping admission for the old epoch.
2. Finish assembly of the control message that defines the cut.
3. Reserve and dispatch it as the final old-epoch outbound ticket.
4. Drain all admitted old-epoch Seal and Open jobs.
5. Commit inbound completions in arrival order.
6. Put every completed old-epoch ciphertext, including the cut message, into the ordered carrier queue.
7. Stop old worker goroutines and wait for them to return.
8. Install new core keys.
9. Construct one fresh per-worker AEAD pair from the new epoch material.
10. Clear reachable old keys, job slots, nonce scratch, and plaintext storage.
11. Resume admission.

Installing new keys while an old Open job is active can authenticate old traffic after the protocol state crossed the cut. Installing while an old Seal job is active can emit an old-epoch message after a new-epoch message. Both are forbidden.

## 8. Stage 5 core diff

### 8.1 Store reachable epoch key material and epoch bytes

Patch `winn_protocol_experimental/winn3/core/session.go`:

```diff
@@
     sendMu      sync.Mutex
     sendAEAD    cipher.AEAD
+    sendKey     [KeySize]byte
     sendSalt    [nonceSaltSize]byte
@@
     sentBytes   uint64
+    epochSentBytes uint64
@@
     recvMu     sync.Mutex
     recvAEAD   cipher.AEAD
+    recvKey    [KeySize]byte
@@ func (s *Session) installEpoch(epoch uint32) error {
     s.sendAEAD = sa
+    s.sendKey = send.key
@@
     s.sendCounter = 0
+    s.epochSentBytes = 0
@@
     s.recvAEAD = ra
+    s.recvKey = recv.key
@@ func (s *Session) wipeLocked() {
     s.sendAEAD = nil
     s.recvAEAD = nil
+    s.sendKey = [KeySize]byte{}
+    s.recvKey = [KeySize]byte{}
+    s.epochSentBytes = 0
@@ func (s *Session) NeedsRekey() bool {
-    return s.sendCounter >= RekeyAfterMessages || s.sentBytes >= RekeyAfterBytes
+    return s.sendCounter >= RekeyAfterMessages ||
+        s.epochSentBytes >= RekeyAfterBytes
@@ func (s *Session) sealInto(dst, payload []byte, padTo int, allocate bool) ([]byte, error) {
     s.sendCounter++
     s.sentBytes += uint64(len(out))
+    s.epochSentBytes += uint64(len(out))
```

This makes lifetime telemetry and epoch rekey policy separate. Keep `SentBytes()` as lifetime telemetry. Add `EpochSentBytes()` for assertions and remove the duplicate `session.Driver.epochBytes` authority after differential tests.

### 8.2 Two-phase core API

Add `winn_protocol_experimental/winn3/core/parallel.go`:

```go
package core

import (
    "crypto/cipher"
    "encoding/binary"
    "errors"
    "io"

    "golang.org/x/crypto/chacha20poly1305"
)

var ErrEpochChanged = errors.New("winn3: crypto ticket epoch changed")

// CryptoWorker is used by exactly one worker goroutine during one epoch.
type CryptoWorker struct {
    epoch    uint32
    sendAEAD cipher.AEAD
    recvAEAD cipher.AEAD
}

type SealReservation struct {
    epoch      uint32
    counter    uint64
    token      [DemuxTokenSize]byte
    nonce      [AEADNonceSize]byte
    payloadLen int
    wireLen    int
}

type OpenReservation struct {
    epoch   uint32
    counter uint64
    token   [DemuxTokenSize]byte
    nonce   [AEADNonceSize]byte
}

func (r SealReservation) Epoch() uint32  { return r.epoch }
func (r SealReservation) Counter() uint64 { return r.counter }
func (r SealReservation) WireLen() int   { return r.wireLen }
func (r OpenReservation) Epoch() uint32  { return r.epoch }
func (r OpenReservation) Counter() uint64 { return r.counter }

// NewCryptoWorker snapshots both immutable traffic keys from one epoch. It may
// be called only while the session sequencer has stopped ticket admission.
func (s *Session) NewCryptoWorker() (*CryptoWorker, error) {
    s.sendMu.Lock()
    s.recvMu.Lock()
    if s.wiped || s.sendAEAD == nil || s.recvAEAD == nil {
        s.recvMu.Unlock()
        s.sendMu.Unlock()
        return nil, ErrWiped
    }
    sendKey := s.sendKey
    recvKey := s.recvKey
    epoch := s.epoch
    s.recvMu.Unlock()
    s.sendMu.Unlock()

    sendAEAD, err := chacha20poly1305.New(sendKey[:])
    if err != nil {
        clear(sendKey[:])
        clear(recvKey[:])
        return nil, err
    }
    recvAEAD, err := chacha20poly1305.New(recvKey[:])
    clear(sendKey[:])
    clear(recvKey[:])
    if err != nil {
        return nil, err
    }
    return &CryptoWorker{
        epoch: epoch, sendAEAD: sendAEAD, recvAEAD: recvAEAD,
    }, nil
}

// ReserveSeal consumes one nonce and charges the exact padded wire length.
// A reserved ticket is never rolled back, even if its worker or carrier fails.
func (s *Session) ReserveSeal(payloadLen, padTo int) (SealReservation, error) {
    var reservation SealReservation
    if payloadLen < 0 || payloadLen > MaxTransportPayload {
        return reservation, errWrap(
            ErrPayloadTooLarge,
            "transport payload is %d bytes, limit %d",
            payloadLen,
            MaxTransportPayload,
        )
    }
    minimum := TransportOverhead() + payloadLen
    wireLen := minimum
    if padTo != 0 {
        if padTo < minimum {
            return reservation, errWrap(
                ErrTargetLenTooSmall,
                "target %d is below the %d-byte minimum for this message",
                padTo,
                minimum,
            )
        }
        wireLen = padTo
    }

    s.sendMu.Lock()
    defer s.sendMu.Unlock()
    if s.wiped || s.sendAEAD == nil || s.sendPRF == nil {
        return reservation, ErrWiped
    }
    if s.sendCounter >= RejectAfterMessages {
        return reservation, ErrCounterExhausted
    }
    counter := s.sendCounter
    reservation.epoch = s.epoch
    reservation.counter = counter
    reservation.token = s.sendPRF.token(counter)
    copy(reservation.nonce[:nonceSaltSize], s.sendSalt[:])
    binary.BigEndian.PutUint64(reservation.nonce[nonceSaltSize:], counter)
    reservation.payloadLen = payloadLen
    reservation.wireLen = wireLen
    s.sendCounter++
    s.sentBytes += uint64(wireLen)
    s.epochSentBytes += uint64(wireLen)
    return reservation, nil
}

// SealReserved performs only stateless AEAD work. This worker must be owned by
// one goroutine, and dst must not alias payload.
func (w *CryptoWorker) SealReserved(
    dst, payload []byte,
    reservation SealReservation,
) ([]byte, error) {
    if w == nil || w.sendAEAD == nil || reservation.epoch != w.epoch {
        return nil, ErrEpochChanged
    }
    if len(payload) != reservation.payloadLen {
        return nil, errWrap(
            ErrPayloadTooLarge,
            "reserved payload is %d bytes, got %d",
            reservation.payloadLen,
            len(payload),
        )
    }
    if cap(dst) < reservation.wireLen {
        return nil, io.ErrShortBuffer
    }
    out := dst[:reservation.wireLen]
    copy(out[:DemuxTokenSize], reservation.token[:])
    plain := out[DemuxTokenSize : len(out)-AEADTagSize]
    binary.BigEndian.PutUint16(plain[:transportHeaderSize], uint16(len(payload)))
    copy(plain[transportHeaderSize:], payload)
    clear(plain[transportHeaderSize+len(payload):])
    sealed := w.sendAEAD.Seal(
        plain[:0],
        reservation.nonce[:],
        plain,
        out[:DemuxTokenSize],
    )
    return out[:DemuxTokenSize+len(sealed)], nil
}

// ResolveOpen maps a token to a counter without consuming replay state.
func (s *Session) ResolveOpen(msg []byte) (OpenReservation, error) {
    var reservation OpenReservation
    if len(msg) < TransportOverhead() {
        return reservation, ErrShortMessage
    }
    s.recvMu.Lock()
    defer s.recvMu.Unlock()
    if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
        return reservation, ErrWiped
    }
    counter, ok := s.recvWindow.lookup(msg[:DemuxTokenSize])
    if !ok {
        if !s.recvWindow.indexed() {
            return reservation, ErrCallerOwnsWindow
        }
        return reservation, ErrUnauthenticated
    }
    reservation.epoch = s.epoch
    reservation.counter = counter
    copy(reservation.token[:], msg[:DemuxTokenSize])
    copy(reservation.nonce[:nonceSaltSize], s.recvSalt[:])
    binary.BigEndian.PutUint64(reservation.nonce[nonceSaltSize:], counter)
    return reservation, nil
}

// OpenReserved authenticates and decrypts without touching replay state.
func (w *CryptoWorker) OpenReserved(
    dst, msg []byte,
    reservation OpenReservation,
) ([]byte, error) {
    if w == nil || w.recvAEAD == nil || reservation.epoch != w.epoch {
        return nil, ErrEpochChanged
    }
    if len(msg) < TransportOverhead() {
        return nil, ErrShortMessage
    }
    if cap(dst) < len(msg)-DemuxTokenSize-AEADTagSize {
        return nil, io.ErrShortBuffer
    }
    plaintext, err := w.recvAEAD.Open(
        dst[:0],
        reservation.nonce[:],
        msg[DemuxTokenSize:],
        msg[:DemuxTokenSize],
    )
    if err != nil || len(plaintext) < transportHeaderSize {
        return nil, ErrDecrypt
    }
    length := int(binary.BigEndian.Uint16(plaintext[:transportHeaderSize]))
    if transportHeaderSize+length > len(plaintext) {
        return nil, ErrDecrypt
    }
    return plaintext[
        transportHeaderSize : transportHeaderSize+length : transportHeaderSize+length,
    ], nil
}

// CommitOpen consumes replay state after successful AEAD, in arrival order.
func (s *Session) CommitOpen(
    reservation OpenReservation,
    wireLen int,
) error {
    s.recvMu.Lock()
    defer s.recvMu.Unlock()
    if s.wiped || s.recvWindow == nil {
        return ErrWiped
    }
    if reservation.epoch != s.epoch ||
        !s.recvWindow.holds(reservation.counter) {
        return ErrUnauthenticated
    }
    current, ok := s.recvWindow.lookup(reservation.token[:])
    if !ok || current != reservation.counter {
        return ErrUnauthenticated
    }
    s.recvWindow.consumeKnown(reservation.counter, reservation.token[:])
    s.recvdBytes += uint64(wireLen)
    return nil
}

// Wipe releases worker references and clears ticket-independent state. The
// cipher implementations keep private key copies until garbage collection,
// matching Session.Wipe's documented limitation.
func (w *CryptoWorker) Wipe() {
    if w == nil {
        return
    }
    w.sendAEAD = nil
    w.recvAEAD = nil
    w.epoch = 0
}
```

This file compiles only with the `sendKey`, `recvKey`, and `epochSentBytes` field patch above. It deliberately exposes no raw key bytes outside `core`.

### 8.3 Worker pool and ordered completion

Add private structures to `winn_protocol_experimental/winn3/session/parallel.go`:

```go
package session

import (
    "runtime"
    "sync"
    "sync/atomic"

    "winsvpn.local/winnprotocol/winn3/core"
)

type cryptoDirection uint8

const (
    cryptoSeal cryptoDirection = iota + 1
    cryptoOpen
)

type cryptoSlot struct {
    sequence uint64
    direction cryptoDirection
    seal core.SealReservation
    open core.OpenReservation
    input []byte
    output []byte
    result []byte
    err error
    ready atomic.Uint32
}

type cryptoJob struct {
    slot *cryptoSlot
}

type epochPool struct {
    jobs chan cryptoJob
    wake chan struct{}
    wait sync.WaitGroup
    workers int
}

func newEpochPool(session *core.Session, configured, depth int) (*epochPool, error) {
    limit := runtime.GOMAXPROCS(0)
    workers := limit
    if configured > 0 && configured < workers {
        workers = configured
    }
    if workers < 1 {
        workers = 1
    }
    pool := &epochPool{
        jobs: make(chan cryptoJob, depth),
        wake: make(chan struct{}, 1),
        workers: workers,
    }
    built := make([]*core.CryptoWorker, 0, workers)
    for len(built) < workers {
        worker, err := session.NewCryptoWorker()
        if err != nil {
            for _, prior := range built {
                prior.Wipe()
            }
            return nil, err
        }
        built = append(built, worker)
    }
    pool.wait.Add(workers)
    for _, worker := range built {
        go pool.run(worker)
    }
    return pool, nil
}

func (p *epochPool) run(worker *core.CryptoWorker) {
    defer p.wait.Done()
    defer worker.Wipe()
    for job := range p.jobs {
        slot := job.slot
        switch slot.direction {
        case cryptoSeal:
            slot.result, slot.err = worker.SealReserved(
                slot.output, slot.input, slot.seal)
        case cryptoOpen:
            slot.result, slot.err = worker.OpenReserved(
                slot.output, slot.input, slot.open)
        default:
            slot.err = core.ErrEpochChanged
        }
        slot.ready.Store(1)
        select {
        case p.wake <- struct{}{}:
        default:
        }
    }
}

func (p *epochPool) stopAndWait() {
    close(p.jobs)
    p.wait.Wait()
}
```

The pool does not itself preserve order. `Driver` owns two fixed completion rings and two monotonic pairs:

```go
sealReserveSequence uint64
sealEmitSequence    uint64
openReserveSequence uint64
openCommitSequence  uint64
```

A ring index is `sequence % uint64(len(ring))`. Admission blocks when the target slot is still owned. Workers publish `result` and `err` before `ready.Store(1)`. The sequencer reads `ready.Load()`, verifies the exact stored sequence to reject ABA reuse, commits, clears sensitive bytes, then resets `ready` to zero.

### 8.4 Exact `session.Driver` split

Replace `assembleInto` with three operations:

```go
type preparedMessage struct {
    plaintext []byte
    targetLen int
    minimumLen int
    hooks [4]func() error
    hookCount int
    barrierAfter bool
}

func (d *Driver) prepare(now time.Time, dst []byte) (preparedMessage, error)
func (d *Driver) reserveSeal(prepared preparedMessage, slot *cryptoSlot) error
func (d *Driver) emitReadySeals(now time.Time) error
```

`prepare` performs the current frame selection and shaping at `winn_protocol_experimental/winn3/session/driver.go:1777-1868`, but no AEAD and no hook. `reserveSeal` calls `core.Session.ReserveSeal`, assigns a sequence, and dispatches the slot. `emitReadySeals` walks only from `sealEmitSequence`, appends ciphertext to the carrier-owned pending queue, calls `noteSent`, then executes hooks.

The current `hooks []func() error` can allocate. Replace it with the fixed array above. The existing frame set can attach at most one epoch-changing hook to the message; assert overflow instead of growing.

Split `Deliver` similarly:

```go
func (d *Driver) reserveOpen(msg []byte, slot *cryptoSlot) error
func (d *Driver) commitReadyOpens(now time.Time) ([][]byte, error)
```

`reserveOpen` resolves the token and dispatches without holding `d.mu` during AEAD. `commitReadyOpens` walks arrival order, calls `core.Session.CommitOpen` only after worker success, then runs the current `ParseFrames` and `handleFrames` logic under the sequencer. Unknown tokens and AEAD failures occupy ordered completion slots with an error so later arrivals can advance.

Handshake messages stay on the current scalar path because no transport session exists yet. ML-KEM, ML-DSA, Ed25519, and X25519 state transitions remain sequencer operations. Only established transport Seal and Open use the epoch pool.

### 8.5 Exact `driver.Loop` integration

`winn_protocol_experimental/winn3/driver/loop.go` becomes an I/O owner, not a crypto owner:

- `readLoop` receives up to 16 descriptors, assigns their array order to `session.Driver.DeliverBatch`, then drains ready inbound commits.
- `drain` asks `session.Driver.PollBatch` for up to the free carrier-slot count, then sends the ordered ready prefix.
- `PollBatch` can return fewer than requested because an earlier crypto sequence is still running.
- `readLoop` signals `wake` when completions arrive. The epoch pool has one coalescing wake channel, not one allocation or goroutine per ticket.
- Carrier generation migration never invalidates crypto tickets. Completed ciphertext is session-owned until one carrier commits it.
- `Loop.Close` stops admission, cancels the carrier generation, drains or accounts all slots, stops the epoch pool, then wipes the session.

Suggested API:

```go
func (d *Driver) PollBatch(dst []carrier.BatchMsg) (int, error)
func (d *Driver) DeliverBatch(src []carrier.BatchMsg) (int, error)
func (d *Driver) StopWorkers()
func (d *Driver) WorkerStats() WorkerStats
```

To keep package layering clean, move the neutral packet descriptor to a small `winn3/packet` package or define a session-local descriptor. `session` must not import `carrier`, because the core session is designed to hold no socket or address. The signature above is illustrative of the loop boundary; the landed signature must use the neutral descriptor type.

## 9. Correctness invariants

### 9.1 Nonce and order

- For one epoch and direction, every reserved counter is unique and strictly increasing.
- Counter reservation order equals ciphertext emission order.
- A carrier successful prefix is the only event that releases ciphertext slots.
- Retrying sends exact bytes. It never invokes AEAD again.
- A dropped worker ticket remains a consumed counter and named drop.
- Arrival sequence, not counter order, controls inbound frame effects and DATA delivery.

### 9.2 Replay

- Token lookup is read-only with respect to replay consumption.
- AEAD failure consumes nothing.
- Commit rechecks token, counter, epoch, and live window.
- Exactly one authentic duplicate can commit.
- A corrupt first copy cannot block a later authentic copy.
- A valid first copy causes every later duplicate to fail commit without delivery.

### 9.3 Epoch

- No old-epoch worker exists after new keys are installed.
- No new-epoch ticket is admitted before the old completion rings drain.
- The final old-epoch control ciphertext enters the carrier queue before the hook installs new keys.
- Old key material reachable from Go fields is cleared before admission resumes.
- An epoch mismatch is local failure state and never produces a distinguishable wire response.

### 9.4 Backpressure

- Every queue has a fixed bound.
- Full outbound queues stop TUN reads or count explicit local drops according to configured policy.
- Full inbound queues stop carrier reads, letting kernel buffers provide bounded pressure.
- Gateway scheduling is fair across sessions. One hot session cannot occupy every shared arena slot.
- No slow client causes an unbounded completion map or goroutine count.

## 10. Verification suites

### 10.1 Current baseline commands

```sh
cd winn_protocol_experimental
go test -race ./winn3/...
go vet ./winn3/...
go test ./cdatapath
cd ..
sh tools/verify_rulings.sh
```

Observed in this study:

| Check | Result |
|---|---|
| `go vet ./winn3/...` | PASS |
| `go test ./cdatapath` | PASS, 0.512 s |
| `tools/verify_rulings.sh` | PASS, all 59 general and 6 Apple invariant checks |
| `go test -race ./winn3/...` | PARTIAL FAIL, all runtime packages passed except redteam fixture and VCS-environment failures |
| explicit `-race` command for every non-redteam package | PASS |

Fresh core benchmark command:

```sh
go test -run '^$' \
  -bench 'BenchmarkAstra(IntoRoundTrip|CachedDemux)$' \
  -benchmem -benchtime=1s -count=3 ./winn3/core
```

Observed on Apple M5 Max, Darwin arm64, Go package suffix `-18`:

| Case | Range | Allocation |
|---|---:|---:|
| cached demux | 80.39 to 85.39 ns/op, 11.71 to 12.44 Mpps | 0 B/op, 0 allocs/op |
| round trip, 64 bytes | 656.3 to 663.1 ns/op, 96.51 to 97.52 MB/s | 0 B/op, 0 allocs/op |
| round trip, 512 bytes | 1472 to 1484 ns/op, 344.93 to 347.82 MB/s | 0 B/op, 0 allocs/op |
| round trip, 1200 bytes | 2326 to 2375 ns/op, 505.22 to 516.02 MB/s | 0 B/op, 0 allocs/op |
| round trip, 1400 bytes | 2642 to 2668 ns/op, 524.71 to 529.86 MB/s | 0 B/op, 0 allocs/op |

These fresh numbers support the mission's allocation claim and approximately reproduce its large-packet bandwidth. They do not measure a socket, a native bridge, parallel scaling, or an end-to-end VPN.

### 10.2 Stage 3 unit tests

Add to `winn_protocol_experimental/winn3/carrier`:

- `TestUDPRecvBatchConnectedIPv4`
- `TestUDPRecvBatchExplicitPeerCompactsWithoutCopy`
- `TestUDPRecvBatchRejectsMSGTRUNC`
- `TestUDPRecvBatchRejectsMSGCTRUNC`
- `TestUDPRecvBatchReturnsSuccessfulPrefixWithError`
- `TestUDPSendBatchReturnsCommittedPrefix`
- `TestUDPSendBatchRejectsEmptyBeforeSyscall`
- `TestUDPSendBatchRejectsOversizeBeforeSyscall`
- `TestUDPBatchNeverReturnsZeroNil`
- `TestUDPBatchCloseUnblocks`
- `TestUDPLifetimeCancelUnblocksReadAndWrite`
- `TestUDPOldLifetimeCannotPoisonRebind`
- `TestUDPBatchScalarFallbackIsStickyPerDirection`
- `TestUDPBatchConcurrentSetPeerUsesOnePeerSnapshot`

The partial-send negative control uses a fake batch backend that records descriptor pointers and returns `(3, syscall.ENOBUFS)`. Assert that descriptors 0 through 2 are released, descriptors 3 through N retain the same backing addresses and bytes, and no session poll happens until the suffix is committed or explicitly dropped.

Allocation gates:

```go
func TestUDPBatchSteadyStateAllocations(t *testing.T) {
    allocations := testing.AllocsPerRun(10_000, func() {
        // Use a preinitialized fake backend so the test measures descriptor
        // reuse and accounting rather than kernel scheduling.
        if _, err := carrier.SendBatch(context.Background(), messages); err != nil {
            panic(err)
        }
    })
    if allocations != 0 {
        t.Fatalf("SendBatch allocations = %v, want 0", allocations)
    }
}
```

The real-socket benchmark reports allocations separately. `context.Background()` exercises the generation-bound fast path only after `BindLifetime` uses the same context.

### 10.3 Linux syscall and offload tests

Unit tests are not syscall proof. Run inside a network namespace with loopback and veth variants:

```sh
strace -f -c -e trace=recvmmsg,sendmmsg,recvmsg,sendmsg,recvfrom,sendto \
  ./winn3-batch-harness -packets 1000000 -batch 32

perf stat -r 10 \
  -e cycles,instructions,cache-misses,context-switches,cpu-migrations \
  ./winn3-batch-harness -packets 1000000 -batch 32
```

Required cases:

- connected IPv4 and IPv6
- unconnected gateway listener with explicit source addresses
- batch sizes 1, 4, 8, 16, 32, and 64
- mixed packet sizes and equal padded buckets
- forced partial send and `ENOBUFS`
- cancellation while idle and under burst
- carrier migration with a pending suffix
- foreign-source spray mixed into valid traffic
- GSO capability on and off
- GRO capability on and off
- route and NIC with offload supported, and loopback or virtual device where it falls back

Acceptance:

- Linux captures at least one `recvmmsg` call returning more than one descriptor.
- Linux captures at least one `sendmmsg` call committing more than one descriptor.
- At batch 32, median UDP syscalls per datagram is at most 0.10 under a saturated equal-size run.
- The steady Go hot path is 0 B/op and 0 allocs/op after initialization.
- Packet capture offload-on and offload-off outputs have identical ordered UDP payload hashes.
- No segment exceeds the active path message ceiling.
- No IPv4 aggregate exceeds 65,507 bytes and no GSO call represents more than 64 datagrams.

GRO adverse corpus:

- missing control message
- control data shorter than two bytes
- segment size zero
- segment size greater than aggregate
- short final segment
- `MSG_TRUNC`
- `MSG_CTRUNC`
- one corrupt middle Winn datagram surrounded by valid datagrams

The corrupt middle message increments unopenable once. The later valid segment still authenticates and commits.

### 10.4 Stage 4 Apple tests

Go and ABI:

- scalar versus batch byte equivalence for 1 through 64 packets
- input count 0, 65, and negative
- nil descriptor array
- nil buffer in every position
- capacity smaller than length
- batch queue partial prefix
- close during blocking first dequeue
- timeout before first packet
- timeout after a successful prefix
- mixed IPv4 and IPv6 protocol array
- fixed-ring wrap and saturation
- zero steady allocations after construction

Swift:

- `packets.count == protocols.count` enforcement
- descriptor pointer lifetime for the complete native call
- partial native result treated as failure unless a retry queue owns the suffix
- one `writePackets` invocation for N returned packets
- callback re-arming after every `readPackets` completion
- stop while both pumps are blocked
- extension memory at ring depth and maximum MTU

Device gate:

- physical iPhone and physical Mac packet-tunnel run
- 100 start and stop cycles
- IPv4 and IPv6 traffic
- route exclusion, DNS, and default-route leak capture
- batch ratios greater than 1.0 under load in both directions
- no extension memory-pressure termination in a 30-minute saturation soak

### 10.5 Stage 4 Android tests

Plain JVM tests:

- packet-batch encode and decode round trip for 1 through 32 packets
- exact payload ceiling
- zero count, 33 count, zero length, truncated length, trailing bytes
- scalar peer and batch-capable peer negotiation
- old engine rejection does not lead the host to send a batch opcode
- fixed-slot ring wrap, full drop, close wake, and generation swap
- no `ByteArray.copyOf` in either production pump
- real packaged Go binary interop, not only a fake transport

Android source checks must confirm that the stale AWG payload comments are gone and all v3 frame contracts say inner IP.

Project policy requires this exact physical-phone smoke procedure for the implementation commit:

```sh
adb uninstall org.winsvpn.app
adb install build/app/outputs/flutter-apk/app-release.apk
adb shell monkey -p org.winsvpn.app -c android.intent.category.LAUNCHER 1
adb logcat -c
adb logcat
```

Capture:

- Perfetto scheduling and syscall trace
- Java and native allocation counts
- GC pauses
- TUN reader generation transitions
- packet batch depth distribution
- local-socket writes per packet
- upload and download throughput
- CPU-seconds per GiB
- energy and thermal state
- re-establish promotion with traffic before, during, and after descriptor swap
- protected outer socket mark and no routing loop

Acceptance:

- no per-packet `ByteArray` allocation in the steady pump path
- mean packets per framed batch above 4 at saturated load
- no unbounded queue, thread, or descriptor growth
- one old reader can remain blocked after the single promotion, but it must own no reusable slot and must exit at service teardown or be recorded as the existing bounded Android limitation
- release APK launches and carries traffic on the connected phone

### 10.6 Stage 4 Windows tests

Compile matrix:

```sh
GOOS=windows GOARCH=amd64 go test ./cmd/winn-datapath
GOOS=windows GOARCH=arm64 go test ./cmd/winn-datapath
GOOS=windows GOARCH=amd64 go vet ./cmd/winn-datapath
GOOS=windows GOARCH=arm64 go vet ./cmd/winn-datapath
```

Windows unit tests:

- no `device.kind:loopback-udp` in the v3 supervisor profile after cutover
- no resolution or launch of `winsvpn_winn3_engine.exe` on the direct path
- Wintun receive always releases exactly once
- Wintun send uses allocate then send, in order
- ring-full returns a named drop, not a tunnel deadlock
- quit event interrupts an idle read
- shutdown waits for both owners before `End`
- adapter readiness precedes route installation
- promotion predicate remains engine-authenticated receive plus carrying gate
- rollback can still select the old two-process path during the staged release

Physical Windows gates:

- amd64 and arm64 where both are shipped
- 100 start and stop cycles
- 30-minute full-duplex soak
- ETW proves the loopback UDP path is absent
- no receive stall longer than one second
- bootstrap route, outer endpoint pin, default route, DNS, and IPv6 posture captured before and after promotion
- process crash and service crash leave no adapter, route, or DNS residue

### 10.7 Stage 5 equivalence and race tests

Core two-phase differential suite:

- one million randomized scalar `SealInto` versus `ReserveSeal` plus `SealReserved` comparisons using identical initial sessions, payload, counter, padding, and epoch
- scalar `OpenInto` versus `ResolveOpen`, `OpenReserved`, and `CommitOpen`
- payload lengths 0, 1, 64, 512, 1200, configured maximum, and 65,535 where the carrier permits
- every padding bucket
- counter 0, rekey threshold minus 1, rekey threshold, and reject threshold minus 1
- corrupt token, ciphertext, tag, inner length, and padding
- replay, reorder, duplicate, and window-wrap cases
- corrupt first copy followed by valid copy
- valid duplicate workers completing in both possible orders
- epoch barrier during a slow final old-epoch Seal and Open
- send partial prefix across carrier migration
- queue full and cancellation at every ownership state

The deterministic slow-worker test assigns sequence 0 to a blocked worker and sequences 1 through 31 to fast workers. Assert that no later ciphertext is visible to the carrier until sequence 0 completes. Repeat for inbound delivery.

Nonce audit records `(epoch, direction, counter, key hash, nonce)` for every reservation in a test build. It must find no repeated `(key hash, nonce)` pair. Test logs store only one-way test-key hashes, never production material.

Run:

```sh
go test -race -count=20 ./winn3/core ./winn3/session ./winn3/driver ./winn3/carrier
go test -run 'TestParallel|TestEpochBarrier|TestCorruptThenValid' \
  -count=1000 ./winn3/core ./winn3/session ./winn3/driver
go test -fuzz FuzzParallelOpenCommit -fuzztime=30m ./winn3/core
go test -fuzz FuzzOrderedCompletion -fuzztime=30m ./winn3/session
```

### 10.8 Stage 5 benchmarks

```sh
go test -run '^$' \
  -bench 'BenchmarkParallel(Seal|Open|RoundTrip|Barrier|FullDuplex)' \
  -benchmem -benchtime=3s -count=10 ./winn3/core ./winn3/session
```

Measure workers 1, 2, 4, 8, and captured `GOMAXPROCS`. Report:

- packets per second
- payload MB/s and wire MB/s
- ns per packet
- B/op and allocs/op
- p50, p95, p99 queue delay
- completion head-of-line wait
- worker utilization
- epoch barrier duration
- CPU-seconds per GiB
- energy on mobile
- drops by named reason

Proposed scaling gates, where hardware has the corresponding suitable cores:

| Workers | Minimum speedup over one worker |
|---:|---:|
| 2 | 1.70x |
| 4 | 3.20x |
| 8 | 5.60x |

These are engineering targets, not assumptions. Mobile may deliberately ship fewer workers if energy, heat, or p99 latency fails even when throughput rises.

## 11. End-to-end acceptance

Run identical randomized back-to-back AWG and Winn v3 trials on each physical platform. Hold hardware, link, endpoint, MTU, routes, DNS, traffic generator, duration, warmup, power mode, and thermal starting state constant.

Workloads:

- iperf3 TCP at 1, 4, 8, and 32 streams
- upload and download separately
- UDP stepped offered load to the loss or queue-delay limit
- 64-byte, 512-byte, 1200-byte, and maximum inner packets
- 10-minute maximum-load run
- 30-minute thermal soak on mobile
- ratchet under full load
- carrier migration with a partial pending batch
- Android TUN promotion under load
- Windows start, promote, stop under load
- Apple extension memory pressure

Product floor:

- every valid pair reaches at least 90 percent of AWG throughput
- CPU-seconds per GiB and energy are no worse than 110 percent of AWG
- no valid pair has an unexplained drop, leak, route, teardown, replay, nonce, or epoch failure

Parity claim:

- geometric mean v3 to AWG throughput ratio at least 1.00
- lower 95 percent confidence bound at least 0.95
- no valid pair below 0.90
- CPU-seconds per GiB no worse than 105 percent of AWG
- p99 added RTT no worse than 10 percent or 5 ms, whichever is larger

A component benchmark, simulator, cross-compile, interface counter, or worker-pool unit test cannot satisfy this gate.

## 12. Rollout and stop conditions

### Commit sequence

1. Restore complete Git provenance and regenerate the redteam verdict artifact.
2. Correct the core lifetime-byte versus epoch-byte authority and add tests.
3. Land neutral batch descriptors and lifetime binding with scalar behavior unchanged.
4. Land Linux `recvmmsg` and `sendmmsg`, tests, metrics, and sticky fallback.
5. Integrate driver receive and pending-send batches without GSO or GRO.
6. Prove Linux syscall reduction.
7. Land GSO send for eligible equal-size runs, then GRO split in a separate commit.
8. Land the Apple batch ABI and fixed Go rings, then Swift arrays.
9. Land Android fixed slots and negotiated batch frames. Run the mandated physical phone test.
10. Move Wintun into `winn-datapath` behind a rollback flag. Run physical Windows proof before removing the relay executable.
11. Land two-phase core crypto and one-worker equivalence mode.
12. Land ordered worker pools with worker count forced to 1 by default.
13. Pass hostile correctness, race, and epoch-barrier suites.
14. Enable automatic worker count by platform after scaling and energy evidence.
15. Run the randomized AWG comparison and freeze the evidence set.

### Immediate stop conditions

- any repeated `(key, nonce)` pair
- any corrupt copy that suppresses a later authentic copy
- any replay double-delivery
- any new-epoch emission before the old cut ciphertext
- any old-epoch commit after new keys install
- any partial-send reseal
- any unbounded queue, goroutine, thread, descriptor, or native memory growth
- any packet boundary difference with GSO or GRO enabled
- any Android protected-socket routing loop
- any Apple packet and protocol array count mismatch
- any Windows Wintun ring access after `End`
- any ruled-invariant failure
- any end-to-end leak, route, DNS, or teardown regression

## 13. Status matrix

| Item | Study verdict | Current proof |
|---|---|---|
| Optional batch-carrier architecture | PASS | reviewed against current carrier and existing internal relay batch code |
| Linux mmsg implementation | UNIMPLEMENTED | official API and local dependency support reviewed |
| Android raw mmsg | UNIMPLEMENTED | `x/net` Android scalar behavior confirmed from source |
| Darwin UDP syscall batching | NOT AVAILABLE THROUGH CURRENT `x/net` | one-message fallback confirmed |
| Linux GSO and GRO | UNIMPLEMENTED | kernel contract reviewed, no live capability probe |
| generation lifetime cancellation | UNIMPLEMENTED | current per-packet allocation site confirmed |
| Apple descriptor-array ABI | UNIMPLEMENTED | current scalar loops confirmed |
| Apple physical extension performance | UNVERIFIED | no device run in this study |
| Android fixed-slot and batch-frame bridge | UNIMPLEMENTED | current allocation and copy path confirmed |
| Android direct TUN ownership | DESIGN ONLY | needs FD rebind and ownership protocol |
| Android physical release APK | UNVERIFIED | no Android source changed, so no install was authorized by this report-only task |
| Windows direct Wintun integration | DESIGN ONLY | current two-process topology confirmed |
| Windows physical runtime | UNVERIFIED | current source itself records this boundary |
| two-phase core crypto API | DESIGN AND REFERENCE DIFF | not applied to workspace |
| ordered worker pool | DESIGN AND REFERENCE DIFF | not applied to workspace |
| fresh scalar core allocation | PASS | benchmark reproduced 0 B/op, 0 allocs/op |
| fresh broad race suite | PARTIAL FAIL | redteam artifact and VCS environment failures remain |
| Stage 3 release gate | NO-GO | implementation and Linux proof absent |
| Stage 4 release gate | NO-GO | implementations and physical device proof absent |
| Stage 5 release gate | NO-GO | implementation, hostile tests, and scaling proof absent |

## 14. Scope note about the embedded diffs

The code blocks above define exact types, ownership, state transitions, and patch surfaces. They are not represented as a fabricated one-shot patch claiming to compile across Go, Swift, Kotlin, Linux, Android, Darwin, and Windows. That claim cannot be made from this checkout for three concrete reasons:

1. The Git object database and revision identity are absent.
2. Stage 4 requires files outside the requested list, including the normative duplex framing, Android process startup, the Windows supervisor, `winn-datapath` device selection, and packaging.
3. Stage 5 requires core `Session` changes before `session.Driver` and `driver.Loop` can parallelize without breaking nonce, replay, byte-budget, and ratchet rules.

Treat the embedded code as the implementation contract for ordered commits, not as release-ready bytes. The safe next artifact is an ordered patch series in a complete clone, with each commit compiled and tested on its target. Calling incomplete snippets a complete compilable cross-platform diff would hide the exact integration risks this study identified.

## 15. Final recommendation

Implement in this order: generation-bound cancellation and Linux mmsg, driver pending batches, Apple batch ABI, Android negotiated batch frames, direct Windows Wintun, then two-phase multicore crypto. Add GSO and GRO only after ordinary batching is proven. Enable more than one crypto worker only after one-worker byte equivalence and hostile epoch tests pass.

The likely first large device gain is Stage 4 because current Apple, Android, and Windows bridges add foreign-call, allocation, process, or loopback work around every packet. Stage 3 removes syscall overhead on Linux and Android outer UDP. Stage 5 then scales the core after I/O can keep multiple workers fed. The three stages are cumulative. None alone proves wire-speed parity.

