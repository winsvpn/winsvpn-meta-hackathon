# Winn Protocol v3 Speed Optimization Deep Study: 5.6 Sol

- **Model**: `gpt-5.6-sol` (extra high reasoning)
- **Completed**: 2026-09-14 05:12:35 UTC
- **Exit code**: 0
- **Wall clock limit**: 21600s (timed out: False)

## Deep Study Report & Implementation Plan

# Winn Protocol v3 speed study

Date: 2026-09-14  
Scope: `winn_protocol_experimental/winn3`, gateway, client bindings, and current platform packet pumps  
Host used for local Go diagnostics: Apple M5 Max, Darwin arm64, Go 1.27.0  
Verdict: **NO-GO for an AWG parity claim. The present v3 data path is allocation-heavy, scalar, and serialized. The cryptographic primitive is not the main system bottleneck.**

## 1. Executive result

Winn v3 can retain ML-KEM-768, X25519, ChaCha20-Poly1305, and its current 8-byte demux-token wire format while removing most of the measured CPU and allocation tax. It cannot reach a defensible zero-allocation claim through `sync.Pool` alone, nor can it become multicore by placing goroutines around the existing `Seal`, `Open`, `Poll`, and `Deliver` methods. Their ownership and locking contracts force copies and serialize state.

The implementation needs five coordinated changes:

1. Add caller-owned packet slots and in-place AEAD APIs. Keep the existing allocating APIs as compatibility wrappers.
2. Make one sequencer own counters, epoch transitions, frame state, and replay commits. Give only immutable epoch work to parallel crypto workers.
3. Keep the HMAC-SHA256 token formula for wire compatibility, but eliminate `hmac.New` and `Sum(nil)` from the packet path. Prefer the existing allocation-free gateway construction first, then benchmark a fixed-input implementation with precomputed SHA-256 chaining states.
4. Add optional batch carrier and batch device interfaces. Implement `recvmmsg` and `sendmmsg` on Linux first. Add UDP GSO and GRO only after exact datagram-boundary tests.
5. Remove platform seams that turn every packet into multiple language-boundary or process-boundary copies. Android needs a fixed slot ring and ultimately an in-process engine. Apple must preserve the packet arrays NetworkExtension already supplies. Windows should connect Wintun directly to the Go engine. Linux should pass one or more TUN fds directly to the engine.

The highest-value ordering is:

```text
correctness blockers
    => allocation-free token and core buffers
    => batch UDP and direct platform packet APIs
    => ordered multicore crypto
    => Linux GSO, GRO, and multiqueue TUN
    => physical-device AWG comparison
```

Do not change the demux PRF, reduce padding, weaken replay behavior, make replay persistence asynchronous, or replace the TUN drain barrier to win a benchmark. Those changes alter security or observable behavior.

## 2. Evidence boundary and provenance

The workspace contains `.git/HEAD`, `.git/config`, and `.git/index`, but no Git object database. Both `git status` and `git rev-parse HEAD` returned `fatal: not a git repository`. Findings are therefore bound to file hashes, not a commit.

| File | SHA-256 |
|---|---|
| `winn_protocol_experimental/winn3/core/session.go` | `3f84e88a060ba146708c5f578e824891520a20609bca5e72076b3f4c05be9eb2` |
| `winn_protocol_experimental/winn3/core/replay.go` | `2256af309a305e341a66f65646e4464723c26b95678f468555b96cb32bdeb54d` |
| `winn_protocol_experimental/winn3/core/index.go` | `cf878f5b988d0dcd58441e5324dc46038d4e2775cbe80ef33362337e264fdb6a` |
| `winn_protocol_experimental/winn3/carrier/udp.go` | `b85d8708f639aedfb80ce9476e6cdab7e3d696965a997bad7179bb905fad2271` |
| `winn_protocol_experimental/winn3/carrier/carrier.go` | `76cf6ea2ef9e9e8e34c38597291f7ca17ccb140917eac535f11280880cc14b03` |
| `winn_protocol_experimental/winn3/driver/loop.go` | `00a9e40cd64e9192f96a9c291b564d42ac9bd29600aafae50297d61a6cc7f610` |
| `winn_protocol_experimental/winn3/session/driver.go` | `0f2257320214d3a460729fd1760c69e1ef5bc81726a603876a3b7489ae54067f` |
| `winn_protocol_experimental/winn3/tun/tun.go` | `cbb84e8d4ef987d1f641c2947242d80acea93221efdae6796120f9da83c87916` |
| `winn_protocol_experimental/winn3/tun/gate.go` | `5c93ec23a50ac7651a4f0beb972ce43dfc02025491dc6cbce9897fe93da98e4c` |
| `winn_protocol_experimental/clientbinding/binding.go` | `c11388c583633e5dd8530be3e67b957e31c2acaf49a793036b2d952059a06c98` |
| `winn_protocol_experimental/datapath/duplex/duplex.go` | `9310ea13787ec1c3333011b398e6924bfe4d5fa1dff3860a78366c6130296a29` |
| `winn_protocol_experimental/winn3/gateway/token.go` | `abde455dabd28ffbb2cc747788ee2945f676002a7e3265062b001ff0538360fe` |
| `winn_protocol_experimental/winn3/gateway/table.go` | `fd9aa33290508d574ece7f37bbbf077b2172be96f6dc51e83564656928c270c6` |
| `winn_protocol_experimental/winn3/gateway/entry.go` | `31774ae2582a27b851480f4992b9ed2155b6eb3ebd4d3d21bfa1064a0e53755e` |
| `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt` | `1585ea9647527ea6787fc3678f29d5f74cee41e737fb62cc71d15e64e57d75c0` |
| `android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt` | `4847f9677d4fbebb483a48a22089e095b8d9a9f782748789df15ab983b9f3595` |
| `android/app/src/main/kotlin/org/winsvpn/app/WinnProtocolFraming.kt` | `f701d462d1791d595483e74b9536882c43e5e7527750b1a7d66b3894de52e62b` |
| `apple/WinsTunnelCore/WinsWinn3Datapath.swift` | `53dbf01ce92a579c5452934bba51fd94e4a22f47756c26378c4b8eccf2d3fe03` |
| `windows/winn3_engine/main_windows.go` | `9b5a10d5a30466a5ec0ffd2c5ee00dc6e0b24abe959030d2a7a94194d50255a4` |
| `windows/winn3_engine/relay.go` | `ec17fb8c2217fc2f3c99850ef4c097153d8749e30f0c26fee4e181ea89030545` |
| `linux/runner/linux_winn3_host.cc` | `e044a66edb83bebb7df3e0f5cf6573c2aa34fcabfd752c15facd375e42306d42` |
| `winn_protocol_experimental/cdatapath/winn_datapath_winn3.go` | `6d59ea3b301cb983c3dbaa4106edb7a643e87bc12c29598bfab015ea5e0c1228` |

This study performed read-only inspection plus temporary local benchmark tests. The temporary tests are not product changes and were removed after the measurements. No platform binary, deployment, route, remote, or user device was changed.

Validation run from `winn_protocol_experimental/`:

```text
go test -count=1 ./winn3/core ./winn3/session ./winn3/carrier ./winn3/driver ./winn3/tun

ok  winsvpn.local/winnprotocol/winn3/core
ok  winsvpn.local/winnprotocol/winn3/session
ok  winsvpn.local/winnprotocol/winn3/carrier
ok  winsvpn.local/winnprotocol/winn3/driver
ok  winsvpn.local/winnprotocol/winn3/tun
```

The gateway, C datapath bridge, and client binding also passed targeted tests. The client binding build needed VCS stamping disabled because this workspace has no usable Git object database:

```text
go test -count=1 ./winn3/gateway ./cdatapath
GOFLAGS=-buildvcs=false go test -count=1 ./clientbinding

ok  winsvpn.local/winnprotocol/winn3/gateway
ok  winsvpn.local/winnprotocol/cdatapath
ok  winsvpn.local/winnprotocol/clientbinding
```

An expanded `go test -count=1 ./winn3/... ./clientbinding/... ./cdatapath/...` was also attempted. The target packages above passed, as did the other ordinary Winn packages. `winn3/redteam` was not green because its generated `build/redteam_verdicts.txt` artifact is absent and its binary tests require usable VCS metadata. The first client-binding attempt hit the same VCS-stamping failure, then passed with `GOFLAGS=-buildvcs=false` as shown above. Regenerate the red-team artifact in a complete checkout before treating the repository-wide suite as green.

These package tests prove the inspected behavior is internally consistent. They do not prove throughput, allocation-free operation, device correctness, or release readiness.

## 3. Measured baseline

### 3.1 Winn v3 local Go microbenchmarks

Command shape:

```text
go test ./winn3/core -run '^$' -bench '^BenchmarkSpeedProbe' -benchmem -benchtime=2s -count=5
go test ./winn3/session -run '^$' -bench '^BenchmarkSpeedProbe' -benchmem -benchtime=2s -count=5
```

| Path | Median range | Payload throughput | Heap bytes/op | Allocations/op |
|---|---:|---:|---:|---:|
| `demuxToken` | 237.2 to 250.1 ns | n/a | 536 | 8 |
| `Session.Seal`, 1420-byte payload | 1.723 to 1.816 us | 782.0 to 824.2 MB/s | 3,632 | 12 |
| `Seal` plus indexed `Open`, 1420 bytes | 4.056 to 4.226 us | 336.0 to 350.1 MB/s | 8,328 | 39 |
| `Seal` plus `OpenAt`, 1420 bytes | 3.166 to 3.396 us | 418.1 to 448.6 MB/s | 6,720 | 15 |
| Full session driver one-way, 1100 bytes | 3.882 to 4.433 us | 248.2 to 283.3 MB/s | 10,720 | 46 |

Interpretation:

- `OpenAt` removes 24 allocations per round trip and reduced latency by roughly 20 to 27 percent in this local diagnostic. The gateway already has the architectural seam, but the session driver always calls `Open`, so the normal driver path cannot use it yet (`winn3/session/driver.go:807-874`, `winn3/core/index.go:143-163`).
- At 90,000 packets/s, the 1100-byte driver result extrapolates to about 965 MB/s of allocation traffic and 4.14 million heap allocations/s. At the 113,636 packets/s required for 1 Gb/s of 1100-byte payload, it is about 1.22 GB/s and 5.23 million allocations/s. This is an allocation-rate extrapolation, not a throughput result.
- The current single-thread core benchmark is fast enough to encrypt more than 1 Gb/s of large packets in isolation. The historical platform results are much lower. The gap points to packet ownership, queues, syscalls, language bridges, and serialization.

Allocation profile for the indexed 1420-byte round trip:

| Site | Approximate allocation-space share |
|---|---:|
| `Session.Seal` | 37.0 percent flat, 43.4 percent cumulative |
| `openCounterLocked` | 18.5 percent flat, 56.5 percent cumulative |
| ChaCha slice growth | 18.5 percent flat |
| `sha256.New` | 12.3 percent flat |
| `hmac.New` | 11.1 percent flat, 23.4 percent cumulative |
| `demuxToken` | 26.0 percent cumulative |
| token-window consume and retirement | 19.6 and 12.9 percent cumulative |

The CPU profile was dominated by ChaCha, Poly1305, HMAC/SHA, allocation, GC, runtime waits, and virtual-memory work. Cache-miss counters were not captured on this Darwin host, so this report does not invent L1 or L2 miss rates.

### 3.2 Isolated allocation-free prototype

All exact patches in Section 13 were applied to a disposable copy at `/tmp/winn3_sol_report_compile_20260914`. The original product source was not edited. The benchmark below measures the core effect of Patches 1, 3, 4, and 7. The copy passed `go test ./winn3/core`; the session, carrier, driver, and TUN packages also compiled. A full session test in the copy could not locate `lib/winn_protocol_dispatch.dart` because that file is outside the copied module. The corresponding original-tree session suite passed before the copy was made.

Command shape:

```text
go test -run '^$' -bench 'BenchmarkProposed' -benchmem -count=5 ./winn3/core
```

| Proposed path | Fresh local range | Payload throughput | Heap bytes/op | Allocations/op |
|---|---:|---:|---:|---:|
| Allocation-free wire-compatible `demuxToken` | 146.6 to 147.0 ns | 6.802 to 6.819 Mpps | 0 | 0 |
| Caller-owned Seal plus `OpenAtInPlace`, 64 bytes | 589.0 to 591.5 ns | 108.2 to 108.7 MB/s | 0 | 0 |
| Caller-owned Seal plus `OpenAtInPlace`, 512 bytes | 1.373 to 1.388 us | 369.0 to 372.9 MB/s | 0 | 0 |
| Caller-owned Seal plus `OpenAtInPlace`, 1420 bytes | 2.539 to 2.576 us | 551.3 to 559.2 MB/s | 0 | 0 |
| Seal plus indexed `OpenInPlace`, 1420 bytes | 3.099 to 3.110 us | 456.6 to 458.3 MB/s | 0 | 0 |

Against the current indexed 1420-byte path, the prototype removes 8,328 B/op and 39 allocations/op and lowers latency by about 23 to 27 percent. Against the current `OpenAt` path, it removes 6,720 B/op and 15 allocations/op and lowers latency by about 20 to 25 percent. These are core microbenchmarks, not end-to-end throughput or AWG parity proof.

The first in-place prototype still allocated 40 B/op in three allocations because local token and nonce arrays escaped through the `cipher.AEAD` interface. `go test -gcflags='all=-m=2'` located the escapes. Moving the mutable nonce and token scratch arrays into `Session`, under the existing direction mutexes, removed them. Parallel workers must use per-worker scratch, never these shared session fields without equivalent exclusion.

### 3.3 Historical physical-platform evidence

These are older fleet snapshots. They are not proof for the current file hashes.

| Platform | No-VPN baseline | Standalone v3 | Retained | Evidence |
|---|---:|---:|---:|---|
| Android | 47.8 Mb/s | 10.2 Mb/s | 21.4 percent | `docs/evidence/vpn-perf/fleet-v4/verdict.txt:11-43` |
| Linux | 626.8 Mb/s | 137.6 Mb/s | 22.0 percent | `docs/evidence/vpn-perf/fleet-v4/linux-verdict.txt:31-59` |
| macOS | 439.9 Mb/s | 135.3 Mb/s | 30.8 percent | `docs/evidence/vpn-perf/fleet-v4/macos-lane-report.txt:8-26` |

Windows fleet evidence in `docs/evidence/vpn-perf/fleet-v4/T-W-REPORT.md:6-11,42-49,64-70` is direct AWG, not standalone v3. The 99.9785 percent result in `winn_protocol_experimental/WINN_PROTOCOL_V3_CONTINUATION_LOG.md:2499-2588` is also direct AWG. Neither can support a v3 parity claim.

### 3.4 AmneziaWG comparison boundary

The official `amneziawg-go` repository was inspected at commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`. Its built-in benchmark reported:

| Official AWG Go benchmark | Fresh local range | What it measures |
|---|---:|---|
| `BenchmarkLatency` | 68.4 to 84.3 us/op, 1,103 to 1,182 B/op, 18 allocs/op | Two channel-TUN ping/pong sends |
| `BenchmarkThroughput` | 8.537 to 9.078 us/op, 516 to 728 B/op, 5 allocs/op | 32-byte ICMP packets through two in-memory devices, with a custom receive-time metric |

The AWG throughput benchmark uses a 32-byte packet made by `tun/tuntest/tuntest.go:17-79`, reports a custom elapsed receive metric, and sends until `b.N` packets arrive (`device/device_test.go:429-470`). It is not comparable to Winn's 1420-byte core microbenchmark or the 1100-byte session benchmark. It is included only to document the current upstream test shape.

The relevant architectural comparison is direct: wireguard-go documents the outbound stages as TUN read, sequential route, sequential nonce assignment, parallel encryption, and sequential transmission. It creates encryption and decryption workers per CPU and uses pooled packet containers. See [official wireguard-go send path](https://git.zx2c4.com/wireguard-go/tree/device/send.go?id=ecfc5a8d5446) and [official device worker creation](https://git.zx2c4.com/wireguard-go/tree/device/device.go?id=12269c276173).

No same-host, same-packet, same-TUN, same-network AWG versus v3 benchmark was run here. The user's observed AWG wire-speed result is the acceptance target, not a result reproduced by this study.

## 4. Current data path and serialization

### 4.1 Outbound

```text
OS TUN, one packet
    |
    v
tun.Tunnel.Outbound
Gate RLock, validate, atomic counters
    |
    v
driver session.Enqueue
Driver mutex, allocate, copy, slice append
    |
    v
driver session.Poll and assemble
Driver mutex, grow plaintext slice, append frames
    |
    v
core Session.Seal
sendMu, HMAC object graph, plaintext allocation, output allocation, AEAD
    |
    v
driver Loop.drain
gate sync, carrier lookup, one Send
    |
    v
UDP carrier
deadline arm, one Write syscall, stats locks
```

### 4.2 Inbound

```text
UDP carrier
deadline arm, one ReadFromUDP, allocate and copy
    |
    v
driver readLoop, one message
    |
    v
session Driver.Deliver under one driver mutex
core Open under recvMu, ParseFrames allocation, state transitions
    |
    v
copy each DATA frame
    |
    v
tun.Tunnel.Inbound
Gate RLock, validate, one device WritePacket
```

Full duplex is serialized by `session.Driver.mu`, not merely by `core.Session.sendMu` and `recvMu`. Outbound `Enqueue` and `Poll` use the same mutex as inbound `Deliver`, which holds it across AEAD open, frame parsing, ML-KEM or rekey handling, and output copying (`winn3/session/driver.go:664-683,724-745,807-874,1880-1968`). The core advertises one concurrent sender and receiver (`winn3/core/session.go:78-87`), but the layer above prevents it.

## 5. Allocation and contention inventory

### 5.1 Core transport

| Operation | Per-packet work | Source |
|---|---|---|
| Token derivation | `hmac.New(sha256.New, key)`, two `Write` calls, `Sum(nil)`, returned slice copy | `winn3/core/replay.go:428-443` |
| Seal | `plain := make`, payload copy, `out := make`, AEAD append | `winn3/core/session.go:323-365` |
| Open | `AEAD.Open(nil, ...)`, output `make`, output copy | `winn3/core/session.go:377-436` |
| Indexed replay lookup | 8-byte token copy and Go map lookup | `winn3/core/replay.go:552-560` |
| Replay consume | token re-derivation for delete, bool-array update, possible repeated retire and new token HMAC | `winn3/core/replay.go:583-626` |
| Frame parse | grows `[]Frame` through append | `winn3/core/frame.go:102-125` |

The token map has no independent map lock. It is protected by `Session.recvMu`. The contention point is `recvMu` and, at a gateway entry, `Entry.mu`, not an internal map mutex (`winn3/core/session.go:103-108`, `winn3/gateway/entry.go:147-167`).

`tokenWindow` mixes three concerns: token-to-counter lookup, replay state, and sliding-window maintenance (`winn3/core/replay.go:446-474`). The external gateway path already separates lookup from replay and lets `OpenAt` keep only the counter window (`winn3/core/index.go:85-163`). Measured session storage was about 38,448 bytes with the private token index versus about 1,456 bytes in caller-owned mode. The normal driver cannot use caller-owned mode because `Deliver` calls `sess.Open`, not `OpenAt` (`winn3/session/driver.go:819`).

### 5.2 Session driver

| Operation | Per-packet work | Source |
|---|---|---|
| Enqueue | one allocation, full packet copy, data slice append under `d.mu` | `winn3/session/driver.go:664-683` |
| Assemble | growing plaintext slice, frame header and payload copies, hook slice growth | `winn3/session/driver.go:1727-1808` |
| Poll | clock/tick, queue work, and Seal all under `d.mu` | `winn3/session/driver.go:724-745` |
| Deliver | Open, ParseFrames, control processing, and output construction under `d.mu` | `winn3/session/driver.go:807-874` |
| DATA output | one allocation and copy per inner packet | `winn3/session/driver.go:1880-1892` |
| Queue pop | slices advance without clearing retired pointer slots | `winn3/session/driver.go:737-742,1738-1772,1775-1788` |

The un-cleared queue entries retain packet backing arrays until the old queue backing array becomes unreachable. Clearing before reslicing is a low-risk memory-retention fix, but it does not solve packet ownership.

### 5.3 UDP carrier and driver loop

| Operation | Current cost | Source |
|---|---|---|
| UDP send | one `Write` or `WriteToUDP`, two stats/state lock sections | `winn3/carrier/udp.go:362-412` |
| UDP receive | serialized read, one `ReadFromUDP`, several lock sections, `make` and copy | `winn3/carrier/udp.go:420-474` |
| Cancellation | per operation channel, closure, `context.AfterFunc`, two deadline updates | `winn3/carrier/udp.go:496-531` |
| Driver send | one Poll, gate sync, carrier lookup, Send, and atomic accounting per message | `winn3/driver/loop.go:531-559` |
| Driver receive | one Recv, sequential Deliver, inner loop, and wake per message | `winn3/driver/loop.go:591-657` |
| Carrier lookup | `l.mu` lock per output message | `winn3/driver/loop.go:810-823` |
| Idle wait | constructs and stops a timer for each future deadline | `winn3/driver/loop.go:562-588` |

`context.AfterFunc` and deadline changes are Go runtime and netpoll operations. They should not be mislabeled as two kernel syscalls on every OS. Escape analysis confirms the callback and channel escape. Their exact syscall count must be measured with `strace`, `perf trace`, DTrace, or ETW on the target.

The shared gateway listener is also scalar: `cmd/winn3-gateway/main.go:1673-1715` reads one UDP datagram, and session pipes write one datagram at `:1903-1907`. Batching only the per-session carrier would miss the gateway's actual socket owner.

### 5.4 TUN and bindings

The generic TUN device exposes scalar `ReadPacket` and `WritePacket` calls (`winn3/tun/params.go:214-240`). `PumpOutbound` correctly allocates one reusable maximum packet buffer rather than one buffer per read, but performs one read and one `Outbound` call per packet (`winn3/tun/tun.go:655-693`).

The gate `RWMutex` is a security barrier. It stays held through enqueue or device write so `Set(StateDown)` cannot return while a packet is still crossing (`winn3/tun/gate.go:174-187,227-246`). Replacing it with an atomic boolean would weaken the kill switch. A batch API should acquire one read hold for a bounded batch and release it after the complete batch, preserving the same drain guarantee.

The public client binding is not a wire-speed packet API. `SendPacket(packet string)` converts a string to bytes and sends one framed packet (`clientbinding/binding.go:348-359`). The duplex writer holds a mutex and performs separate header and payload writes (`datapath/duplex/duplex.go:191-240`). That framing channel may be optimized because it is an internal process seam. The carrier stream's one-write-per-Winn-message rule must remain unchanged because it is a pinned traffic-shape property (`winn3/carrier/stream.go:27-44,282-345`).

## 6. GC and cache model

The allocation rate, not the live payload size alone, explains the GC pressure. Go's GC guide identifies allocation rate as a major driver of collection frequency and recommends eliminating heap allocations after profiles show that GC is material. See [Go GC guide](https://go.dev/doc/gc-guide).

At 1 Gb/s, a 1420-byte payload rate is about 88,028 packets/s before outer overhead. A 64-byte workload is about 1.95 million packets/s. Per-packet allocation that looks tolerable at full MTU becomes dominant for DNS, ACK-heavy TCP, interactive traffic, and small UDP.

Expected cache behavior, to be verified rather than assumed:

- Go maps scatter buckets and require pointer-rich lookups. A fixed open-addressed token table keeps control bytes, tokens, and counters in compact arrays and removes growth.
- A `[]bool` replay window consumes one byte per counter. A `[]uint64` bitset reduces a 1024-counter window from 1024 bytes to 128 bytes and makes checks simple indexed bit operations.
- A single global packet pool can bounce cache lines among workers. Use per-worker free rings, steal from a global overflow ring only when local rings empty, and return a slot to the worker that will use it next.
- Keep hot slot metadata within one 64-byte line where practical: sequence, length, counter, epoch pointer, state, and error code. Put producer and consumer indices on separate padded lines to avoid false sharing. Verify offsets and contention with benchmarks.
- Packet bytes should be contiguous and have fixed headroom for the 8-byte token plus tailroom for the 16-byte tag. Avoid `[][]byte` inside the hot ring. Store integer slot indexes in queues so the GC scans few pointers.

`sync.Pool` is useful for compatibility-path spill buffers, but it does not prove zero allocations. The Go contract permits pool entries to be removed at any time. A bounded, explicitly owned free ring is required for deterministic steady-state zero allocation. See [Go sync.Pool documentation](https://pkg.go.dev/sync#Pool).

Proposed slot layout for a 2048-byte arena slot:

```text
metadata cache line
+--------+--------+---------+---------+----------+---------+
| seq 8B | ctr 8B | epoch 8B| len 4B  | state 4B | padding |
+--------+--------+---------+---------+----------+---------+

packet bytes
+-------------+----------------------+-----------------+
| token 8B    | inner length + data  | AEAD tag 16B    |
+-------------+----------------------+-----------------+
```

The ring size is a tuning parameter. Start with 1024 or 2048 slots per direction, then measure queue delay and memory on each platform. Do not allocate a 2048-slot ring per session on a high-cardinality gateway. Use shared worker arenas plus bounded per-session descriptor queues.

## 7. Correctness blockers before parallel work

Performance work must begin with three state bugs. Parallel execution will make each harder to diagnose.

### 7.1 Perpetual rekey after the byte threshold

`Session.sentBytes` is cumulative (`winn3/core/session.go:96-101`). Epoch installation resets `sendCounter` but not `sentBytes` (`:128-173`). `NeedsRekey` compares that cumulative value to the per-epoch `RekeyAfterBytes` limit (`:301-315`). The driver resets its separate `epochBytes` at `winn3/session/driver.go:2131` and `:2305`, but that does not reset core.

Once core reaches its 64 GiB threshold, each successful rekey installs a new epoch whose `NeedsRekey` is already true. Add a separate `epochSentBytes`, reset it in `installEpoch`, and keep `sentBytes` cumulative for public accounting.

### 7.2 DATA can inherit a state transition from an earlier frame

`Deliver` authenticates one plaintext, clears rekey confirmation, parses its frames, then calls `handleFrames` (`winn3/session/driver.go:819-874`). `handleFrames` reevaluates `dataMayFlow()` at each DATA frame (`:1880-1892`). An authenticated plaintext containing a final PQ, dual-auth, or rekey control frame followed by DATA can move the state and cause later DATA in that same old-boundary plaintext to be accepted.

Snapshot DATA eligibility after successful Open and confirmation clearing, but before any frame changes state. Use that value for every DATA frame in the plaintext. Add hostile tests for `[PQ_CT, DATA]`, `[final dual auth, DATA]`, and `[REKEY_ACK, DATA]`.

### 7.3 Unlocked dual-auth state

`DualAuthVerified` reads `dualDone` without `d.mu` at `winn3/session/driver.go:557-561`; inbound frame handling writes it under `d.mu` at `:2090-2116`. Lock the accessor or make the field atomic. The lock is consistent with every other driver state accessor and avoids a data race under the [Go memory model](https://go.dev/ref/mem).

## 8. Zero-allocation steady-state design

### 8.1 Ownership is the actual API problem

The present signatures force allocation:

- `Carrier.Recv(ctx) ([]byte, error)` promises a caller-owned returned slice.
- `Session.Enqueue(inner []byte)` must copy because the caller retains ownership.
- `Session.Poll() ([]byte, error)` returns storage with no release contract.
- `Session.Deliver(msg) ([][]byte, error)` constructs a slice and independent inner-packet buffers.
- `tun.Device.ReadPacket` and `WritePacket` carry one packet and no ownership token.

Zero allocation requires explicit slot ownership. Keep these APIs for compatibility and add a fast path whose ownership is mechanically visible.

```go
type PacketSlot struct {
    Buffer []byte
    Length int
    Seq    uint64
    Counter uint64
}

type SlotLease interface {
    Slot() *PacketSlot
    Release()
}
```

Production code should use integer slot IDs in SPSC or MPSC rings instead of interface values. The interface above explains the contract: a stage owns the slot until it transfers or releases it. No stage may retain a byte slice after release.

Recommended buffers:

- A bounded arena allocates every packet slot during tunnel startup.
- Each slot has enough headroom and tailroom for token, encrypted length, maximum shaped message, and AEAD tag.
- The TUN reader writes directly into the frame payload region where the platform permits it.
- Frame assembly writes into the same slot after the 8-byte token position.
- AEAD seals the plaintext in place with `plain[:0]` as destination.
- UDP batch descriptors point directly at sealed slot bytes.
- Receive batches fill free slots directly. AEAD opens `ciphertext[:0]` in place.
- TUN output consumes the authenticated payload view, then releases the slot.

The official Go AEAD contract explicitly permits `Seal(plaintext[:0], ...)` and `Open(ciphertext[:0], ...)` for exact in-place overlap. It also states that `Open` may overwrite destination capacity even when authentication fails. A failed slot must be discarded or fully reinitialized before reuse. See [crypto/cipher.AEAD](https://pkg.go.dev/crypto/cipher#AEAD).

### 8.2 In-place packet geometry

For a packet arena slice `b`:

```text
b[0:8]                          token and AAD
b[8:10]                         encrypted payload length
b[10:10+payloadLength]          encoded frames
b[10+payloadLength:plainEnd]    zero padding
b[plainEnd:plainEnd+16]         AEAD tag after Seal
```

Seal sequence:

```go
plain := b[8:plainEnd]
ciphertext := aead.Seal(plain[:0], nonce[:], plain, token[:])
copy(b[:8], token[:])
wire := b[:8+len(ciphertext)]
```

Open sequence:

```go
token := b[:8]
ciphertext := b[8:wireLength]
plain, err := aead.Open(ciphertext[:0], nonce[:], ciphertext, token)
```

Do not call `aead.Seal(b[:8], ...)` while plaintext starts at `b[8:]`. That is overlapping storage outside the exact `plaintext[:0]` form promised by the interface.

### 8.3 Frame parsing without allocations

The hot DATA case does not need `[]Frame`. Parse and dispatch in one pass:

1. Read the 3-byte frame header.
2. Bounds-check the value.
3. For DATA, pass a capacity-clipped view to the ordered commit stage.
4. For control, copy only the small or explicitly retained value into control storage.
5. Continue until the authenticated plaintext is exhausted.

An alternative is `ParseFramesInto(dst []Frame, b []byte)`, with stack or slot metadata sized for the maximum frames per message. The streaming form is better because it cannot overflow a frame-metadata array and avoids retaining a pointer-rich slice.

### 8.4 Zero allocation versus zero copy

These are separate goals:

- Allocation-free Seal and Open are straightforward with a reusable arena.
- Zero-copy Android and Apple boundaries are not guaranteed because Java `ByteArray`, Swift `Data`, cgo/JNI, and NetworkExtension own different lifetimes.
- Wintun offers borrowed receive buffers and allocated send-ring buffers. A true no-copy path needs crypto APIs that understand those lifetimes.
- Linux TUN and UDP normally still copy between user and kernel. Batching reduces syscall and scheduling cost, not those kernel copies.

The first acceptance target is zero Go heap allocations in steady-state core, driver rings, and batch carrier. Then measure copies per platform and remove them where ownership permits.

## 9. Ordered multicore crypto pipeline

### 9.1 Outbound pipeline

```text
batch TUN ingress
    |
    v
single session sequencer
validate state, assemble frames, assign seq and counter, snapshot epoch keyset
    |
    +====> crypto worker 0 ====+
    +====> crypto worker 1 ====+====> ordered completion ring ====> UDP batch send
    +====> crypto worker N ====+
```

The sequencer is the sole writer of:

- send counter and byte budget
- shape decisions
- control-frame ordering
- post-Seal hooks
- epoch transition state
- per-session output sequence

Workers receive an immutable job:

```go
type sealJob struct {
    slot     uint32
    seq      uint64
    counter  uint64
    epoch    *epochKeyset
    plainEnd uint16
}
```

`epochKeyset` contains a per-worker AEAD instance, nonce salt, demux PRF state, epoch number, and an in-flight reference count. Build all worker AEADs from the derived traffic key before zeroing the temporary key. Do not assume the `cipher.AEAD` interface promises concurrent method safety. Each worker uses only its own AEAD object.

The ordered sender reads completion slots by `seq`. It may wait for a slow earlier job while later jobs are ready. This head-of-line wait is required to preserve the current per-session send order. Use one ready flag per slot with release/acquire synchronization, not one mutex per packet.

Nonce safety rules:

- Reserve counters once under the sequencer.
- A carrier send failure never causes resealing.
- If an unsent ciphertext is retried, retry the exact bytes with the same destination. Do not invoke AEAD again.
- A batch send that returns a successful prefix commits that prefix. The exact unsent suffix remains owned by the pending-ciphertext queue.
- Migration must either drain the pending queue on the old carrier or explicitly transfer exact ciphertext ownership. It must never allocate new counters for the same inner packets.

### 9.2 Ratchet barrier

Current hooks ratchet only after the last old-epoch message has been sealed (`winn3/session/driver.go:1824-1832`). Preserve that as a barrier:

1. Stop admitting new outbound DATA for the session.
2. Assign and enqueue every frame that belongs to the old epoch.
3. Wait until all old-epoch seal jobs finish.
4. Publish the last old-epoch ciphertext to the ordered sender.
5. Execute the ratchet hook and install the next immutable keyset.
6. Resume admission under the new epoch.
7. Retire the old keyset only after its in-flight reference count reaches zero and its bytes are wiped.

The sender does not need to wait for the kernel to transmit the last ciphertext before installing local keys, but it must preserve output queue order so that the old control ciphertext is submitted first.

### 9.3 Inbound pipeline

```text
UDP RecvBatch into slots
    |
    v
token demux and arrival sequence assignment
    |
    +====> shard 0, AEAD verify ====+
    +====> shard 1, AEAD verify ====+====> arrival-ordered commit ====> frame state and TUN batch
    +====> shard N, AEAD verify ====+
```

All candidates for the same `(session, epoch, counter)` must go to the same shard. This is required by the current guarantee that a corrupted copy does not consume the slot needed by a later genuine copy (`winn3/core/session.go:367-376`).

Parallel receive must split authentication from replay mutation:

1. Demux maps token to `(session, counter, epoch generation)`.
2. A worker checks a read-only window snapshot and attempts AEAD Open into the slot.
3. The worker does not consume replay state.
4. Ordered commit processes completions in carrier arrival order.
5. On successful authentication, commit rechecks that the counter is still live, consumes it exactly once, and dispatches frames.
6. A failed authentication consumes nothing.
7. A second valid duplicate may have completed crypto, but the commit recheck drops it.

This preserves both corrupted-copy behavior and exactly-once delivery. An atomic `test-and-set` before AEAD is unsafe because a forged first copy could reserve the counter and suppress the genuine packet.

Control-frame processing remains ordered and single-owner. ML-KEM, dual signatures, and X25519 rekey operations are not ordinary DATA crypto jobs. Their cost can move to a control worker only if the owner pauses dependent state and commits the result in order.

### 9.4 Worker count and backpressure

Start with:

```text
crypto workers = min(GOMAXPROCS, physical performance cores observed by platform policy)
batch size = 32 or 64
session descriptor depth = 256
shared slot count = 1024 or 2048 per direction
```

These are benchmark starting points, not defaults to ship. Mobile efficiency cores and thermal behavior can make `GOMAXPROCS` workers slower and more power hungry. Select worker count from sustained throughput, CPU-seconds/GiB, energy, and p99 queue delay.

Every queue is bounded. Overflow increments a named counter and applies explicit backpressure or a documented drop policy. Never grow an unbounded packet queue during congestion.

## 10. Demux PRF and replay window

### 10.1 Keep the current token bytes first

The wire formula is fixed in `winn3/core/index.go:41-53`:

```text
HMAC-SHA256(demuxKey, "winn3 demux v1" || be64(counter))[0:8]
```

Current `demuxToken` constructs a hash graph and allocates a result slice for each call (`winn3/core/replay.go:428-443`). Indexed in-order receive may compute the consumed token, compute it again while retiring the low edge, and compute the new high-edge token (`:583-617`).

The repository already contains an allocation-free equivalent in `winn3/gateway/token.go:58-137`. It builds fixed stack arrays for the HMAC inner and outer messages and calls `sha256.Sum256`. Port this construction into core and retain differential tests against `crypto/hmac` plus existing known-answer vectors.

Compression count needs precise wording:

- Hashing the complete 86-byte inner input from the SHA-256 IV takes two compression blocks.
- Hashing the complete 96-byte outer input from the IV takes two more.
- The stack-array implementation therefore removes allocations but still performs four compressions.
- Precomputing the chaining state after each 64-byte ipad and opad block reduces per-token work to one remaining inner block and one outer block.

The public `hash.Hash` API does not expose a portable chaining-state constructor. A second-stage two-compression implementation must be a small fixed-input SHA-256 routine or a carefully reviewed state-clone design, with differential tests over random keys and counters. Go's SHA-256 implementation selects available assembly paths, so benchmark on each target before assuming hardware acceleration.

### 10.2 Alternatives

| Alternative | Wire compatible | Direct counter recovery | Recommendation |
|---|---:|---:|---|
| Precomputed HMAC-SHA256 state | Yes | No | Preferred for v3 |
| Reusable `hmac.Hash` with Reset | Yes | No | Removes construction only, awkward across workers |
| SipHash token | No | No | Do not introduce a new primitive only for speed |
| Truncated ChaCha PRF | No | No | Does not remove the lookup problem |
| 128-bit AES permutation over structured counter | No, adds 8 bytes | Yes | Evaluate only as a versioned future protocol |
| Custom 64-bit reversible token | No | Yes | Reject without a dedicated cryptographic design |

An AES block can provide a reversible 128-bit pseudorandom permutation, but the current token is 64 bits. Truncating AES loses unique inversion. A 16-byte token would add 8 bytes per datagram and change the fingerprint and protocol version. It is not a local optimization.

### 10.3 Replace map plus byte array carefully

A circular bitmap cannot map a pseudorandom 8-byte token back to its counter. It can replace only the replay-consumed array after the counter is known. The exact v3 choices are:

1. Gateway: use one external sharded token index plus `CallerOwnsTokenWindow` and `OpenAt`. This is already designed and measured smaller (`winn3/core/index.go:6-39`, `winn3/gateway/token.go:152-188`). Integrate a `DeliverAt` path so the gateway session driver can use it.
2. Client or standalone session: replace the Go map with a fixed-capacity open-addressed table storing token, counter, and control byte. The 64-bit HMAC output is already pseudorandom, so low token bits are a reasonable initial bucket. Use backward-shift deletion or bounded rebuild to prevent tombstone accumulation.
3. Replace `[]bool` with a `[]uint64` ring bitset after differential testing across wrap, force-advance, replay, corruption, and randomized reorder.

For a 1024-token window, start with a 2048-entry flat table. Keep control bytes separate so empty/tombstone scans are dense. Treat token zero as an ordinary value rather than an empty sentinel. Probe count and collision count must be exported as diagnostics.

Gateway lookup already has a sharded table, collision handling, and allocation-free miss path (`winn3/gateway/table.go:460-508`). Do not build another private token map behind it.

One source comment must also be corrected before order-sensitive work. `winn3/carrier/udp.go:24-30` says the frame layer re-sorts datagrams into token order. `tokenWindow` accepts reordered counters but does not buffer or re-sort payloads, and `Driver.Deliver` returns DATA immediately. The new commit ring should preserve carrier arrival order to match behavior. Counter order and arrival order are not always the same on a real network.

## 11. UDP batching, GSO, GRO, and syscall reduction

### 11.1 Safe first step: optional datagram batches

Do not widen the four-method `Carrier` interface and force TCP/TLS carriers to fake datagram batching. Add optional interfaces:

```go
type BatchMessage struct {
    Buffer []byte
    N      int
}

type BatchReceiver interface {
    RecvBatch(context.Context, []BatchMessage) (int, error)
}

type BatchSender interface {
    SendBatch(context.Context, [][]byte) (int, error)
}
```

The driver checks these interfaces once when a carrier generation is installed. It keeps a scalar fallback.

On Linux, `golang.org/x/net/ipv4.PacketConn.ReadBatch` and `WriteBatch` map to optimized batch operations. On other Unix systems the package may process only one message, and on Windows these methods are not implemented. See [x/net IPv4 batch API](https://pkg.go.dev/golang.org/x/net/ipv4#PacketConn.ReadBatch) and the [official x/net implementation](https://go.googlesource.com/net/+/master/ipv4/batch.go).

The repository already has a suitable design in `winn_protocol_experimental/internal/carrier/relay_batch.go:15-199` and `internal/carrier/relay.go:94-183`:

- batch size 64 with a hard bound
- IPv4 and IPv6 wrappers
- sticky per-direction fallback
- partial-count handling
- preallocated message descriptors and receive buffers
- source validation and accepted-packet compaction
- buffer clearing and reuse

Port or factor that code instead of inventing a second fallback state machine.

Receive rules:

1. Hold `recvMu` once for the batch call.
2. Arm cancellation once for the blocking read loop, not once per packet.
3. Fill caller-owned slots directly.
4. Reject `MSG_TRUNC` and `MSG_CTRUNC` before parsing.
5. Validate every source address in explicit-peer mode.
6. Compact accepted slots without copying packet bytes by swapping descriptor indexes.
7. Process a successful prefix even when `ReadBatch` also returns an error.
8. Never return `(0, nil)`.
9. Update counts and timestamps once under the stats lock per batch.

Send rules:

1. Validate every message length before reserving counters or calling the kernel.
2. Preserve message order.
3. Interpret `n` as a committed prefix.
4. Keep exact ciphertext for the unsent suffix.
5. Apply a sticky scalar fallback only for capability failures, not transient network errors.
6. Count calls, packets, bytes, partial batches, fallbacks, and retry-suffix depth.

### 11.2 Cancellation and deadlines

`armRead` and `armWrite` currently allocate callback state and change socket deadlines for each operation (`winn3/carrier/udp.go:496-531`). Replace packet-scoped cancellation with loop-scoped interruption:

- At loop start, register one context callback that sets the relevant deadline to `time.Now()` or closes an owned socket.
- Clear the deadline once after the blocked operation returns and the generation is still active.
- For a batch with a real context deadline, set the socket deadline once per batch, not per datagram.
- A gateway-shared socket cannot be closed by one session. Its listener context owns cancellation centrally.

This requires careful generation checks during carrier migration. A stale callback must not set a deadline on a newly installed carrier.

### 11.3 UDP GSO and GRO

Linux `UDP_SEGMENT` can submit up to 64 equal-sized UDP datagrams in one large send. `UDP_GRO` can return multiple datagrams in one buffer plus a control message giving segment size. See [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html) and [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).

GSO constraints for Winn:

- One GSO call uses one segment size. Only consecutive ciphertexts of equal length and the same destination can be concatenated.
- Padding buckets help form equal-length runs, but the sender may not reorder packets merely to length-group them.
- The final segment may be shorter only where the kernel API permits it. Test exact datagram bytes with packet capture.
- Checksums are completed after segmentation. Capability depends on kernel, socket, route, container, and NIC. Kernel version alone is not proof.
- Begin with gateway opt-in. Use `sendmmsg` for mixed sizes and GSO only for eligible runs.

GRO constraints:

- Do not enable GRO while using `ReadFromUDP`. It would present several Winn messages as one byte slice.
- Use OOB-capable batch receive, parse `SOL_UDP/UDP_GRO`, and split by the reported segment size before token demux.
- Reject truncated data or control messages.
- Each resulting segment retains its own arrival sequence and slot ownership.
- Differential tests must show the split segments are byte-identical to GRO-disabled datagrams.

OS support boundary:

| OS | `x/net` batch behavior | UDP GSO/GRO plan |
|---|---|---|
| Linux | Optimized batch syscalls | Supported behind capability probe |
| Android | `GOOS=android`, not the Linux optimized branch in current `x/net` | Use native JNI path only after device proof |
| macOS and iOS | One message per `x/net` batch call | Use NetworkExtension arrays and ordinary UDP calls |
| Windows | `ReadBatch` and `WriteBatch` unimplemented | Use Wintun direct path and Windows socket batching separately |

### 11.4 Gateway ownership

`winn3/gateway.Gateway` owns no socket or goroutine. `Gateway.Handle` accepts an already-received datagram (`winn3/gateway/gateway.go:212-331`). The server loop in `cmd/winn3-gateway/main.go:1673-1715` is the correct receive-batch integration point.

For outbound gateway traffic, per-session pipes currently call one `WriteToUDPAddrPort` at `cmd/winn3-gateway/main.go:1903-1907`. Cross-session batching needs a server-owned writer queue. It must be bounded, own slots until send completion, preserve order within each session, process successful prefixes, and expose per-session backpressure. Measure the extra queue handoff against syscall savings.

### 11.5 Stream carriers

Do not combine multiple Winn messages into one TLS or TCP application write. `winn3/carrier/stream.go:27-44` treats one write per message as an observable traffic-shape rule. Stream receive still allocates its body at `:355-430`, and cancellation has the same deadline/callback pattern at `:500-542`. Add caller-owned `RecvInto` storage and loop-scoped cancellation while retaining exactly one carrier write per Winn message.

The duplex control seam is different. Its two writes at `datapath/duplex/duplex.go:231-239` are an internal framing cost, not an on-wire camouflage rule. A reusable fused buffer or `writev` can reduce that cost.

## 12. Platform packet paths

### 12.1 Android

Current path:

- `VpnTunnelService.kt:2662-2720` establishes the Android VPN descriptor and wraps it in `WinnV3AndroidTunDevice`.
- `WinnV3AndroidTun.kt:33-56` uses `FileInputStream` and `FileOutputStream` on the same descriptor.
- The seam uses `ArrayBlockingQueue<ByteArray>` at `:105-143`.
- The reader allocates `buffer.copyOf(n)` per packet at `:145-171`.
- Dequeue copies again with `System.arraycopy` at `:174-181`.
- Injection copies again at `:201-207`.
- `WinnV3Bridge.kt:183-270` makes another `copyOf` before engine send.
- `WinnProtocolFraming.kt:147-195` allocates a fused header/payload buffer and flushes every frame; receive allocates another array at `:230-313`.
- `WinnEngineTransport.kt:16-47` is scalar.

At least four visible Kotlin copies occur on ordinary outbound packets after the TUN read, before the Go-side copies.

Immediate work:

1. Call `VpnService.Builder.setBlocking(true)` explicitly if retaining a dedicated blocking reader. No current call exists. Android documents that the descriptor is nonblocking by default. The present exception-to-termination path at `WinnV3AndroidTun.kt:145-166` needs idle and burst testing on the USB device. See [Android VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder).
2. Replace `ArrayBlockingQueue<ByteArray>` with a fixed slot ring. Each slot owns a reusable `ByteArray`, length, and descriptor generation.
3. Pass the slot through the bridge and return it only after framing completes.
4. Add offset/length framing APIs and a reusable fused write buffer, or a correct native `writev` implementation.
5. Preserve the per-generation reader needed for descriptor replacement. Allocation removal must not reintroduce a reader stuck on the deactivated descriptor (`WinnV3AndroidTun.kt:59-103,234-249`).
6. Move the Go datapath in process through JNI and pass the TUN fd directly as the larger phase. Keep AF_UNIX only for status/control if descriptor transfer is still needed.
7. Protect the outer socket with `VpnService.protect()` before full-tunnel routes open.

Android `VpnService` exposes one TUN fd, not Linux-style multiqueue configuration. Parallelize validation and crypto behind one read owner and one write owner. Do not simulate multiqueue with concurrent reads on the same Java stream without device evidence.

The project operating rule requires the final Android test on the connected USB-debugging phone: uninstall `org.winsvpn.app`, install `build/app/outputs/flutter-apk/app-release.apk`, launch it, and inspect logcat for startup and VPN errors. That destructive package uninstall and install was outside this read-only study and was not performed.

### 12.2 Apple NetworkExtension

The platform already batches, but the bridge throws batching away:

- `apple/WinsTunnelCore/WinsWinn3Datapath.swift:317-359` receives packet and protocol arrays.
- It loops and calls the C ABI once per packet at `:347-380`.
- Each call resolves symbols and locks the handle at `:363-380`.
- Engine output performs one ABI read and copies into `Data` at `:397-420`.
- It constructs one-element arrays and calls `writePackets` per packet at `:443-461`.
- `cdatapath/winn_datapath_winn3.go:244-273` uses a depth-256 `[][]byte` queue.
- Its read, write, offer, and take operations copy at `:284-400`; timed reads allocate a timer at `:355-400`.
- The exported ABI is scalar at `:1122-1158`.

Apple's API explicitly reads and writes arrays and requires matching packet/protocol counts. See [NEPacketTunnelFlow writePackets](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets%28_%3Awithprotocols%3A%29).

Add a batch C ABI:

```c
typedef struct {
    const uint8_t *bytes;
    int32_t length;
    int32_t protocol_family;
} WinnPacketView;

typedef struct {
    int32_t offset;
    int32_t length;
    int32_t protocol_family;
} WinnPacketDescriptor;

int32_t WinnTunnelWriteInboundBatch(
    uint64_t handle,
    const WinnPacketView *packets,
    int32_t packet_count
);

int32_t WinnTunnelReadOutboundBatch(
    uint64_t handle,
    uint8_t *arena,
    int32_t arena_capacity,
    WinnPacketDescriptor *descriptors,
    int32_t descriptor_capacity,
    int32_t timeout_ms
);
```

Resolve symbols once at startup. Submit the complete `readPackets` array in one call. Drain 32 or 64 packets into a reusable arena, create matching Swift arrays, and call `writePackets` once. Use `autoreleasepool` around sustained batch loops and measure actual extension memory. Apple does not publish one universal NetworkExtension memory ceiling, so no assumed jetsam limit belongs in the acceptance gate.

NetworkExtension does not expose Linux multiqueue TUN configuration. Parallelism belongs behind the packet-flow owner. Validate iPhone and macOS separately because provider memory, scheduling, and copy behavior differ.

### 12.3 Windows and Wintun

Current path:

- `windows/winn3_engine/main_windows.go:148-153` uses 4 MiB Wintun rings.
- It starts a localhost UDP seam and Wintun session at `:250-289`.
- Two goroutines pump between Wintun and loopback at `:337-355`.
- Receive correctly retains the Wintun packet until processing and then releases it at `:487-501`.
- Send calls `AllocateSendPacket`, copies, and commits with `SendPacket` at `:523-536`.
- `windows/winn3_engine/relay.go:66-147` adds one loopback UDP send or receive per packet.

Wintun already exposes the right lifetime model: borrowed receive packet plus release, and allocated send packet plus commit. Its official API also notes that allocation order defines send order and describes adaptive spinning for high rates. See [official Wintun API](https://github.com/WireGuard/wintun/blob/master/README.md).

Target architecture:

1. Link the Go datapath into the Wintun host process.
2. Implement a Wintun-backed batch device directly.
3. Remove the localhost UDP packet seam.
4. Initially keep one copy from Wintun receive memory into a Winn slot and one copy into the Wintun send ring. This is simpler and safe.
5. Then add borrowed-receive and allocate-then-commit output APIs with explicit release rules.
6. Benchmark bounded adaptive spin before waiting. Bound CPU and energy so idle power does not regress.

The installer pins signed Wintun 0.14.1 (`installer/windows/install_winsvpn_zip.ps1:80-99,163-179`). Upstream master has a 2026-03-18 missed-wakeup fix associated with long TCP stalls. Do not ship an ad hoc DLL. Record the running driver version, add a stall detector, and adopt only a properly signed release after independent verification. See [official upstream fix](https://git.zx2c4.com/wintun/commit/?id=ec0a6b98456fe1ba52567bb2add4bbf5f64315a1).

`main_windows.go:80-111` says no real Windows run occurred, while `:393-409` records a later first carry run and teardown race. Treat the earlier comment as stale documentation, not current proof either way. Fresh x64 and ARM64 runs remain required.

### 12.4 Linux

The shipping host opens one `/dev/net/tun` fd with `IFF_TUN | IFF_NO_PI` at `linux/runner/linux_winn3_host.cc:3089-3120`. No `IFF_MULTI_QUEUE` use exists. It has a 2048-slot userspace ring and combines up to 32 framed pipe messages in one write at `:87-104,459-539`, but reads the TUN one packet at a time with a copy at `:542-576` and writes engine output one packet at a time at `:579-630`.

A direct Go TUN-fd backend exists at `winn_protocol_experimental/cmd/winn-datapath/winn3_device_tunfd_linux.go:38-110`, but it accepts one fd and is not the shipping host path.

Target architecture:

1. Open one, two, four, or eight fds with the same interface name and `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE`.
2. Pass every fd to the Go engine through inherited descriptors or `SCM_RIGHTS`.
3. Retain the existing control pipe for status only.
4. Add a batch device interface and one reader per TUN queue.
5. Start with a single ordered writer. Test per-flow write sharding only after packet-reorder measurement.
6. Add virtio-net headers and TUN GSO/GRO only behind capability probes and byte-level packet vectors.

Linux requires repeated `TUNSETIFF` calls with the same device name and `IFF_MULTI_QUEUE`, returning one fd per queue. See [Linux TUN/TAP multiqueue documentation](https://docs.kernel.org/networking/tuntap.html).

Multiqueue alone will not fix v3. If `Session.Open` and `Driver.Deliver` remain serialized, more TUN queues can add reordering and lock contention without increasing crypto throughput.

## 13. Exact staged Go diffs

These are review-ready diffs against the hashed files above. They were not applied to the product tree. Apply and test them in order. Patches 1 through 6 preserve the wire format. Patch 7 adds explicit fast-path APIs while retaining old methods.

### Patch 1: make byte-trigger accounting per epoch

```diff
diff --git a/winn_protocol_experimental/winn3/core/session.go b/winn_protocol_experimental/winn3/core/session.go
--- a/winn_protocol_experimental/winn3/core/session.go
+++ b/winn_protocol_experimental/winn3/core/session.go
@@
-	sendMu      sync.Mutex
-	sendAEAD    cipher.AEAD
-	sendSalt    [nonceSaltSize]byte
-	sendDemux   [KeySize]byte
-	sendCounter uint64
-	sentBytes   uint64
+	sendMu         sync.Mutex
+	sendAEAD       cipher.AEAD
+	sendSalt       [nonceSaltSize]byte
+	sendDemux      [KeySize]byte
+	sendCounter    uint64
+	sentBytes      uint64
+	epochSentBytes uint64
@@
 	s.sendDemux = send.demux
 	s.sendCounter = 0
+	s.epochSentBytes = 0
@@
-	return s.sendCounter >= RekeyAfterMessages || s.sentBytes >= RekeyAfterBytes
+	return s.sendCounter >= RekeyAfterMessages || s.epochSentBytes >= RekeyAfterBytes
@@
 	s.sendCounter++
 	s.sentBytes += uint64(len(out))
+	s.epochSentBytes += uint64(len(out))
 	return out, nil
diff --git a/winn_protocol_experimental/winn3/core/invariants_test.go b/winn_protocol_experimental/winn3/core/invariants_test.go
--- a/winn_protocol_experimental/winn3/core/invariants_test.go
+++ b/winn_protocol_experimental/winn3/core/invariants_test.go
@@
-	cli.sentBytes = RekeyAfterBytes - 1
+	cli.epochSentBytes = RekeyAfterBytes - 1
@@
-	cli.sentBytes = RekeyAfterBytes
+	cli.epochSentBytes = RekeyAfterBytes
@@
 	if cli.SendCounter() >= RekeyAfterMessages {
 		t.Fatal("the message trigger was also satisfied, so this proves nothing about bytes")
 	}
+
+	beforeTotal := cli.SentBytes()
+	if err := cli.Rekey(make([]byte, KeySize)); err != nil {
+		t.Fatal(err)
+	}
+	if cli.NeedsRekey() {
+		t.Fatal("a completed rekey did not reset the per-epoch byte budget")
+	}
+	if got := cli.SentBytes(); got != beforeTotal {
+		t.Fatalf("cumulative SentBytes changed across rekey: got %d, want %d", got, beforeTotal)
+	}
 }
```

### Patch 2: freeze DATA eligibility and fix the accessor race

The wrapper keeps current direct tests of `handleFrames` compiling.

```diff
diff --git a/winn_protocol_experimental/winn3/session/driver.go b/winn_protocol_experimental/winn3/session/driver.go
--- a/winn_protocol_experimental/winn3/session/driver.go
+++ b/winn_protocol_experimental/winn3/session/driver.go
@@
-func (d *Driver) DualAuthVerified() bool { return d.dualDone }
+func (d *Driver) DualAuthVerified() bool {
+	d.mu.Lock()
+	defer d.mu.Unlock()
+	return d.dualDone
+}
@@
 	d.rekeyConfirmAt = time.Time{}
+	dataMayFlowAtOpen := d.dataMayFlow()
@@
-	return d.handleFrames(now, frames, len(msg) >= d.cfg.MaxMessageSize)
+	return d.handleFramesWithDataGate(now, frames, len(msg) >= d.cfg.MaxMessageSize, dataMayFlowAtOpen)
@@
 func (d *Driver) handleFrames(now time.Time, frames []core.Frame, wide bool) ([][]byte, error) {
+	return d.handleFramesWithDataGate(now, frames, wide, d.dataMayFlow())
+}
+
+func (d *Driver) handleFramesWithDataGate(now time.Time, frames []core.Frame, wide, dataMayFlow bool) ([][]byte, error) {
 	var out [][]byte
 	for _, f := range frames {
 		switch f.Type {
 		case core.FrameData:
-			if !d.dataMayFlow() {
+			if !dataMayFlow {
```

Required tests:

- A final old-epoch PQ frame followed by DATA in the same plaintext drops DATA.
- A final old-epoch rekey frame followed by DATA drops DATA.
- A valid new-epoch DATA message clears `rekeyConfirmAt` and is admitted.
- Concurrent `DualAuthVerified`, Deliver, close, and teardown pass `go test -race`.

### Patch 3: allocation-free wire-compatible demux HMAC

```diff
diff --git a/winn_protocol_experimental/winn3/core/replay.go b/winn_protocol_experimental/winn3/core/replay.go
--- a/winn_protocol_experimental/winn3/core/replay.go
+++ b/winn_protocol_experimental/winn3/core/replay.go
@@
-import (
-	"crypto/hmac"
+import (
 	"crypto/sha256"
@@
-func demuxToken(key *[KeySize]byte, counter uint64) [DemuxTokenSize]byte {
-	var ctr [8]byte
-	binary.BigEndian.PutUint64(ctr[:], counter)
-	mac := hmac.New(sha256.New, key[:])
-	mac.Write([]byte(labelDemux))
-	mac.Write(ctr[:])
-	sum := mac.Sum(nil)
+const demuxHMACBlockSize = sha256.BlockSize
+
+var _ [demuxHMACBlockSize - KeySize]byte
+
+func demuxToken(key *[KeySize]byte, counter uint64) [DemuxTokenSize]byte {
+	var token [DemuxTokenSize]byte
+	demuxTokenInto(&token, key, counter)
+	return token
+}
+
+func demuxTokenInto(token *[DemuxTokenSize]byte, key *[KeySize]byte, counter uint64) {
+	var inner [demuxHMACBlockSize + len(labelDemux) + 8]byte
+	for i := 0; i < demuxHMACBlockSize; i++ {
+		inner[i] = 0x36
+	}
+	for i, b := range key {
+		inner[i] ^= b
+	}
+	copy(inner[demuxHMACBlockSize:], labelDemux)
+	binary.BigEndian.PutUint64(inner[demuxHMACBlockSize+len(labelDemux):], counter)
+	innerHash := sha256.Sum256(inner[:])
+
+	var outer [demuxHMACBlockSize + sha256.Size]byte
+	for i := 0; i < demuxHMACBlockSize; i++ {
+		outer[i] = 0x5c
+	}
+	for i, b := range key {
+		outer[i] ^= b
+	}
+	copy(outer[demuxHMACBlockSize:], innerHash[:])
+	sum := sha256.Sum256(outer[:])
+
-	var t [DemuxTokenSize]byte
-	copy(t[:], sum[:DemuxTokenSize])
-	return t
+	copy(token[:], sum[:DemuxTokenSize])
 }
```

Add the differential test below to `winn3/core/vectors_test.go`, with `crypto/hmac`, `crypto/sha256`, and `encoding/binary` imports.

```go
func TestDemuxTokenMatchesStandardHMAC(t *testing.T) {
	var keys [2][KeySize]byte
	for i := range keys[1] {
		keys[1][i] = byte(i)
	}
	counters := []uint64{0, 1, 42, 1 << 63, ^uint64(0)}
	for _, key := range keys {
		for _, counter := range counters {
			var ctr [8]byte
			binary.BigEndian.PutUint64(ctr[:], counter)
			mac := hmac.New(sha256.New, key[:])
			_, _ = mac.Write([]byte(labelDemux))
			_, _ = mac.Write(ctr[:])
			want := mac.Sum(nil)
			got := demuxToken(&key, counter)
			if !hmac.Equal(got[:], want[:DemuxTokenSize]) {
				t.Fatalf("counter %d: got %x, want %x", counter, got, want[:DemuxTokenSize])
			}
		}
	}
}
```

This first version still recomputes ipad and opad bytes and performs four SHA-256 compressions. The isolated prototype measured 0 B/op and 0 allocs/op without changing a token. `demuxTokenInto` is needed by the in-place path so its token scratch does not escape through the `cipher.AEAD` interface. A later precomputed-state version must remain differential-tested against it.

### Patch 4: collapse Seal to one packet allocation and Open to one allocation

```diff
diff --git a/winn_protocol_experimental/winn3/core/frame.go b/winn_protocol_experimental/winn3/core/frame.go
--- a/winn_protocol_experimental/winn3/core/frame.go
+++ b/winn_protocol_experimental/winn3/core/frame.go
@@
-import "encoding/binary"
+import (
+	"encoding/binary"
+	"slices"
+)
@@
 	var hdr [frameHeaderSize]byte
 	hdr[0] = byte(t)
 	binary.BigEndian.PutUint16(hdr[1:], uint16(len(value)))
+	dst = slices.Grow(dst, frameHeaderSize+len(value))
 	dst = append(dst, hdr[:]...)
diff --git a/winn_protocol_experimental/winn3/core/session.go b/winn_protocol_experimental/winn3/core/session.go
--- a/winn_protocol_experimental/winn3/core/session.go
+++ b/winn_protocol_experimental/winn3/core/session.go
@@
-	plain := make([]byte, transportHeaderSize+len(payload)+padLen)
+	plainLen := transportHeaderSize + len(payload) + padLen
+	buf := make([]byte, DemuxTokenSize+plainLen, minLen+padLen)
+	plain := buf[DemuxTokenSize:]
 	binary.BigEndian.PutUint16(plain[:transportHeaderSize], uint16(len(payload)))
 	copy(plain[transportHeaderSize:], payload)
 	// Padding stays zero: it is inside the AEAD and therefore unobservable.
 
-	out := make([]byte, DemuxTokenSize, minLen+padLen)
-	copy(out, token[:])
-	out = s.sendAEAD.Seal(out, nonce[:], plain, token[:])
+	ciphertext := s.sendAEAD.Seal(plain[:0], nonce[:], plain, token[:])
+	out := buf[:DemuxTokenSize+len(ciphertext)]
+	copy(out[:DemuxTokenSize], token[:])
@@
-	out := make([]byte, n)
-	copy(out, plain[transportHeaderSize:transportHeaderSize+n])
-	return out, nil
+	return plain[transportHeaderSize : transportHeaderSize+n : transportHeaderSize+n], nil
 }
```

This is a compatibility-path reduction, not the final zero-allocation API. Open still allocates because it calls `AEAD.Open(nil, ...)`. The returned payload also retains the decrypted padded backing array until release. The capacity limit prevents append from exposing padding, but does not change retention.

### Patch 5: clear queue references and reuse depth-one backing arrays

```diff
diff --git a/winn_protocol_experimental/winn3/session/driver.go b/winn_protocol_experimental/winn3/session/driver.go
--- a/winn_protocol_experimental/winn3/session/driver.go
+++ b/winn_protocol_experimental/winn3/session/driver.go
@@
-		d.hsOut = d.hsOut[1:]
+		d.hsOut = dropFront(d.hsOut)
@@
 // --- assembly ---------------------------------------------------------------
 
+func dropFront[T any](q []T) []T {
+	var zero T
+	q[0] = zero
+	if len(q) == 1 {
+		return q[:0]
+	}
+	return q[1:]
+}
+
 // assemble builds at most one transport message out of the queued frames.
@@
-		d.ctrl = d.ctrl[1:]
+		d.ctrl = dropFront(d.ctrl)
@@
-			d.data = d.data[1:]
+			d.data = dropFront(d.data)
```

Add `plain := make([]byte, 0, budget)` in `assemble` as a temporary compatibility improvement. It changes multiple growth allocations into one predictable allocation. The final fast path should build directly into a packet slot instead.

### Patch 6: optional batch interfaces and timer fast path

Insert after `Carrier` in `winn3/carrier/carrier.go`:

```diff
diff --git a/winn_protocol_experimental/winn3/carrier/carrier.go b/winn_protocol_experimental/winn3/carrier/carrier.go
--- a/winn_protocol_experimental/winn3/carrier/carrier.go
+++ b/winn_protocol_experimental/winn3/carrier/carrier.go
@@
 type Carrier interface {
@@
 }
+
+// BatchMessage is one caller-owned receive buffer.
+// RecvBatch sets N to the received datagram length and never retains Buffer.
+type BatchMessage struct {
+	Buffer []byte
+	N      int
+}
+
+// BatchReceiver is optional datagram acceleration.
+// Implementations return the successfully received prefix even when err is non-nil.
+type BatchReceiver interface {
+	RecvBatch(ctx context.Context, messages []BatchMessage) (int, error)
+}
+
+// BatchSender is optional datagram acceleration.
+// Implementations return the successfully sent prefix and never retain messages.
+type BatchSender interface {
+	SendBatch(ctx context.Context, messages [][]byte) (int, error)
+}
```

Replace `waitForWork` at `winn3/driver/loop.go:564-589`:

```diff
diff --git a/winn_protocol_experimental/winn3/driver/loop.go b/winn_protocol_experimental/winn3/driver/loop.go
--- a/winn_protocol_experimental/winn3/driver/loop.go
+++ b/winn_protocol_experimental/winn3/driver/loop.go
@@
 func (l *Loop) waitForWork(ctx context.Context) error {
+	select {
+	case <-ctx.Done():
+		return ctx.Err()
+	case <-l.wake:
+		return nil
+	default:
+	}
+
 	deadline := l.sess.NextDeadline()
 	if deadline.IsZero() {
 		select {
 		case <-ctx.Done():
 			return ctx.Err()
 		case <-l.wake:
 			return nil
 		}
 	}
 	d := deadline.Sub(l.clock.Now())
 	if d <= 0 {
-		// Already due. Do not build a timer for it; the next Poll consumes it.
 		return ctx.Err()
 	}
 	t := l.clock.NewTimer(d)
 	defer t.Stop()
 	select {
 	case <-ctx.Done():
 		return ctx.Err()
 	case <-l.wake:
 		return nil
 	case <-t.C():
 		return nil
 	}
 }
```

Add a test that preloads `l.wake`, invokes `waitForWork`, and proves the counting clock constructed zero timers. This patch handles the already-ready case only. A reusable timer requires extending the injected `Timer` abstraction with a correctly drained `Reset` operation.

### Patch 7: explicit in-place core API

Add direction-local scratch to `Session`. The current send and receive mutexes protect these fields. Wipe them with the rest of the key material.

```diff
diff --git a/winn_protocol_experimental/winn3/core/session.go b/winn_protocol_experimental/winn3/core/session.go
--- a/winn_protocol_experimental/winn3/core/session.go
+++ b/winn_protocol_experimental/winn3/core/session.go
@@
 	sendCounter    uint64
 	sentBytes      uint64
 	epochSentBytes uint64
+	sendNonceWork  [AEADNonceSize]byte
+	sendTokenWork  [DemuxTokenSize]byte
@@
 	recvWindow *tokenWindow
 	recvdBytes uint64
+	recvNonceWork [AEADNonceSize]byte
@@
 	s.recvDemux = [KeySize]byte{}
+	s.sendNonceWork = [AEADNonceSize]byte{}
+	s.sendTokenWork = [DemuxTokenSize]byte{}
+	s.recvNonceWork = [AEADNonceSize]byte{}
```

Then add these methods to `winn3/core/session.go`. They compile alongside the existing `Seal`, `Open`, and `OpenAt`, preserving compatibility.

```go
// TransportPayloadOffset is the position at which a caller building a packet
// slot places the first payload byte before SealPrepared.
func TransportPayloadOffset() int {
	return DemuxTokenSize + transportHeaderSize
}

// SealPrepared seals a payload already present in packet at
// packet[TransportPayloadOffset():TransportPayloadOffset()+payloadLen].
// It allocates no packet storage. The caller retains packet ownership.
func (s *Session) SealPrepared(packet []byte, payloadLen, padTo int) ([]byte, error) {
	if payloadLen < 0 || payloadLen > MaxTransportPayload {
		return nil, errWrap(ErrPayloadTooLarge, "transport payload is %d bytes, limit %d", payloadLen, MaxTransportPayload)
	}
	minLen := TransportOverhead() + payloadLen
	padLen := 0
	if padTo != 0 {
		if padTo < minLen {
			return nil, errWrap(ErrTargetLenTooSmall, "target %d is below the %d-byte minimum for this message", padTo, minLen)
		}
		padLen = padTo - minLen
	}
	wireLen := minLen + padLen
	if cap(packet) < wireLen {
		return nil, errWrap(ErrConfig, "packet buffer capacity is %d bytes, need %d", cap(packet), wireLen)
	}
	packet = packet[:wireLen]
	plainEnd := wireLen - AEADTagSize
	plain := packet[DemuxTokenSize:plainEnd]
	binary.BigEndian.PutUint16(plain[:transportHeaderSize], uint16(payloadLen))
	clear(plain[transportHeaderSize+payloadLen:])

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.wiped || s.sendAEAD == nil {
		return nil, ErrWiped
	}
	if s.sendCounter >= RejectAfterMessages {
		return nil, ErrCounterExhausted
	}
	counter := s.sendCounter
	demuxTokenInto(&s.sendTokenWork, &s.sendDemux, counter)
	copy(s.sendNonceWork[:nonceSaltSize], s.sendSalt[:])
	binary.BigEndian.PutUint64(s.sendNonceWork[nonceSaltSize:], counter)

	ciphertext := s.sendAEAD.Seal(plain[:0], s.sendNonceWork[:], plain, s.sendTokenWork[:])
	out := packet[:DemuxTokenSize+len(ciphertext)]
	copy(out[:DemuxTokenSize], s.sendTokenWork[:])
	s.sendCounter++
	s.sentBytes += uint64(len(out))
	s.epochSentBytes += uint64(len(out))
	return out, nil
}

// OpenInPlace authenticates and decrypts msg over its own ciphertext storage.
// On failure, bytes in msg after the token may have been overwritten.
func (s *Session) OpenInPlace(msg []byte) ([]byte, error) {
	if len(msg) < TransportOverhead() {
		return nil, ErrShortMessage
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return nil, ErrWiped
	}
	counter, ok := s.recvWindow.lookup(msg[:DemuxTokenSize])
	if !ok {
		if !s.recvWindow.indexed() {
			return nil, ErrCallerOwnsWindow
		}
		return nil, ErrUnauthenticated
	}
	return s.openCounterInPlaceLocked(msg, counter)
}

// OpenAtInPlace is OpenAt with caller-owned mutable packet storage.
func (s *Session) OpenAtInPlace(msg []byte, counter uint64) ([]byte, error) {
	if len(msg) < TransportOverhead() {
		return nil, ErrShortMessage
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return nil, ErrWiped
	}
	if !s.recvWindow.holds(counter) {
		return nil, ErrUnauthenticated
	}
	return s.openCounterInPlaceLocked(msg, counter)
}

func (s *Session) openCounterInPlaceLocked(msg []byte, counter uint64) ([]byte, error) {
	token := msg[:DemuxTokenSize]
	copy(s.recvNonceWork[:nonceSaltSize], s.recvSalt[:])
	binary.BigEndian.PutUint64(s.recvNonceWork[nonceSaltSize:], counter)
	ciphertext := msg[DemuxTokenSize:]
	plain, err := s.recvAEAD.Open(ciphertext[:0], s.recvNonceWork[:], ciphertext, token)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(plain) < transportHeaderSize {
		return nil, ErrDecrypt
	}
	n := int(binary.BigEndian.Uint16(plain[:transportHeaderSize]))
	if transportHeaderSize+n > len(plain) {
		return nil, ErrDecrypt
	}
	s.recvWindow.consume(counter)
	s.recvdBytes += uint64(len(msg))
	return plain[transportHeaderSize : transportHeaderSize+n : transportHeaderSize+n], nil
}
```

Patch 7 assumes Patch 1 because it increments `epochSentBytes`. Add an overlap test, a corrupted-ciphertext slot-reuse test, capacity tests, and byte-for-byte differential tests against current Seal/Open for padded and unpadded messages. The persistent scratch fields are required for zero allocations with Go 1.27 on this host. Local nonce and token arrays escaped through the `cipher.AEAD` interface and measured 40 B/op in three allocations.

It is still serialized by `sendMu` and `recvMu`. The ordered worker architecture requires a later internal API that reserves counters and immutable epoch jobs under the sequencer, then authenticates outside these locks. Each worker must own its own nonce and token scratch arrays.

## 14. Benchmark suite

### 14.1 Core benchmark file

After Patches 1, 3, and 7, add `winn3/core/datapath_benchmark_test.go`:

```go
package core

import (
	"strconv"
	"testing"
)

func benchmarkDataPair(b *testing.B, receiveWindow int) (*Session, *Session) {
	b.Helper()
	ch := newChain([]byte("winn3-datapath-benchmark"))
	sender, err := newSession(RoleInitiator, ch, DefaultTokenWindow)
	if err != nil {
		b.Fatal(err)
	}
	receiver, err := newSession(RoleResponder, ch, receiveWindow)
	if err != nil {
		b.Fatal(err)
	}
	return sender, receiver
}

func reportPacketMetrics(b *testing.B, payloadBytes, packetsPerOp int) {
	b.Helper()
	b.SetBytes(int64(payloadBytes * packetsPerOp))
	b.ReportAllocs()
	seconds := b.Elapsed().Seconds()
	if seconds > 0 {
		packets := float64(b.N * packetsPerOp)
		b.ReportMetric(packets/seconds/1e6, "Mpps")
	}
}

func BenchmarkDemuxToken(b *testing.B) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = demuxToken(&key, uint64(i))
	}
	seconds := b.Elapsed().Seconds()
	if seconds > 0 {
		b.ReportMetric(float64(b.N)/seconds/1e6, "Mpps")
	}
}

func BenchmarkSessionInPlace(b *testing.B) {
	for _, payloadLen := range []int{64, 512, 1420} {
		b.Run(strconv.Itoa(payloadLen), func(b *testing.B) {
			sender, receiver := benchmarkDataPair(b, CallerOwnsTokenWindow)
			slot := make([]byte, TransportOverhead()+payloadLen)
			payload := slot[TransportPayloadOffset():TransportPayloadOffset()+payloadLen]
			for i := range payload {
				payload[i] = byte(i)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				msg, err := sender.SealPrepared(slot[:0], payloadLen, 0)
				if err != nil {
					b.Fatal(err)
				}
				plain, err := receiver.OpenAtInPlace(msg, uint64(i))
				if err != nil {
					b.Fatal(err)
				}
				if len(plain) != payloadLen {
					b.Fatalf("opened %d bytes, want %d", len(plain), payloadLen)
				}
			}
			reportPacketMetrics(b, payloadLen, 1)
		})
	}
}

func BenchmarkSessionIndexedInPlace(b *testing.B) {
	sender, receiver := benchmarkDataPair(b, DefaultTokenWindow)
	const payloadLen = 1420
	slot := make([]byte, TransportOverhead()+payloadLen)
	for i := TransportPayloadOffset(); i < len(slot)-AEADTagSize; i++ {
		slot[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, err := sender.SealPrepared(slot[:0], payloadLen, 0)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := receiver.OpenInPlace(msg); err != nil {
			b.Fatal(err)
		}
	}
	reportPacketMetrics(b, payloadLen, 1)
}
```

The isolated prototype reported `0 B/op, 0 allocs/op` for all benchmarks above after moving AEAD scratch to direction-local session fields. This is a core result only. The DATA-only driver and complete carrier path still need their own zero-allocation proof. If a target compiler regresses, use `go test -gcflags='all=-m=2'` and fix the escape rather than hiding it with a larger pool.

### 14.2 Current driver benchmark

Add `winn3/session/datapath_benchmark_test.go`. This compiles against the current test helpers and gives a stable before measurement:

```go
package session

import "testing"

func BenchmarkDriverOneWay1100(b *testing.B) {
	keys := makeFuzzKeys(b)
	sender, receiver := establish(b, keys)
	payload := make([]byte, 1100)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sender.Enqueue(payload); err != nil {
			b.Fatal(err)
		}
		msg, err := sender.Poll()
		if err != nil {
			b.Fatal(err)
		}
		packets, err := receiver.Deliver(msg)
		if err != nil {
			b.Fatal(err)
		}
		if len(packets) != 1 || len(packets[0]) != len(payload) {
			b.Fatalf("unexpected delivery shape: %d packets", len(packets))
		}
	}
	seconds := b.Elapsed().Seconds()
	if seconds > 0 {
		b.ReportMetric(float64(b.N)/seconds/1e6, "Mpps")
	}
}
```

The optimized suite must add:

- `BenchmarkDriverSlotOneWay` for 64, 512, and configured maximum inner payload
- `BenchmarkDriverSlotRoundTrip`
- `BenchmarkDriverBatch` for batches 1, 4, 16, 32, and 64
- `BenchmarkDriverControlAndData` with realistic PING/PONG and rekey cadence
- `BenchmarkDriverCorruptThenValidDuplicate`
- `BenchmarkDriverRatchetBarrier`
- `BenchmarkDriverQueueFull`
- `BenchmarkDriverFullDuplex`

The final slot benchmark must reach zero steady-state allocations for DATA-only traffic. Control and ratchet cases may allocate initially, but their allocation rate must be reported separately and bounded.

### 14.3 Carrier, TUN, gateway, and binding matrix

| Package | Required cases | Metrics |
|---|---|---|
| `winn3/carrier` | connected/unconnected IPv4 and IPv6, scalar, `RecvInto`, batch 1/8/32/64, foreign spray, cancellation, partial send | ns/packet, Mpps, B/op, allocs/op, syscalls/packet |
| `winn3/tun` | valid IPv4/IPv6, invalid input, scalar versus batch, gate close during batch | ns/packet, Mpps, B/op, allocs/op, drain time |
| `winn3/gateway` | miss, hit, 1/10k sessions, collision overflow, rekey rebase, batch dispatch | ns/packet, probe count, lock wait, bytes/session |
| `cdatapath` | scalar versus batch ABI, queue depths, timer-free waits, saturation | ns/packet, copies/packet, B/op, allocs/op |
| `datapath/duplex` | 64 and maximum frames, two writes versus fused/writev, `net.Pipe` | writes/frame, ns/frame, B/op |
| Windows | Wintun ring plus loopback versus direct | packets/s, CPU, ETW context switches, stalls |
| Android | Kotlin seam, fixed slots, JNI direct | packets/s, allocations, GC, CPU, energy, Perfetto |
| Apple | scalar ABI versus packet arrays | packets/s, Swift allocations, CPU, extension memory |
| Linux | 1/2/4/8 TUN queues, scalar UDP, mmsg, GSO/GRO | packets/s, syscalls/packet, cycles/byte, cache misses |

The repository's gateway tests already provide useful controls:

- Gateway miss: about 6.6 to 8.1 ns/op, 0 B/op, 0 allocs/op.
- Gateway hit with fake opener: about 905 to 987 ns/op, 1 allocation. The fake message allocation is at `winn3/gateway/harness_test.go:55-63`.
- The real authenticated gateway allocation test reports exactly 3 allocations, attributed to core rather than table dispatch (`winn3/gateway/openerat_test.go:879-923`).
- A mocked relay benchmark at batch 64 reports about 326 to 331 ns/packet, 0.03125 batch calls/packet, and zero allocations. That is structural Darwin evidence, not Linux syscall proof.

### 14.4 Benchmark procedure

Microbenchmarks:

```text
go test -run '^$' -bench 'Benchmark(DemuxToken|SessionInPlace|Driver)' -benchmem -benchtime=2s -count=10 ./winn3/core ./winn3/session | tee before.txt
go test -run '^$' -bench 'Benchmark(DemuxToken|SessionInPlace|Driver)' -benchmem -benchtime=2s -count=10 ./winn3/core ./winn3/session | tee after.txt
benchstat before.txt after.txt
```

Randomize before/after binary order to reduce thermal and frequency bias. Build each binary once. Record compiler, flags, OS build, CPU governor or power mode, `GOMAXPROCS`, packet sizes, padding profile, and source hashes.

Profiles:

```text
go test -run '^$' -bench BenchmarkSessionInPlace -benchtime=10s -cpuprofile cpu.pprof -memprofile mem.pprof ./winn3/core
go tool pprof -top cpu.pprof
go tool pprof -sample_index=alloc_space -top mem.pprof
go test -run '^$' -bench BenchmarkDriverFullDuplex -benchtime=10s -trace driver.trace ./winn3/session
go tool trace driver.trace
```

Linux host measurements:

```text
perf stat -r 10 -e cycles,instructions,cache-references,cache-misses,context-switches,cpu-migrations ./winn3-bench
strace -f -c ./winn3-bench
perf record -g ./winn3-bench
```

Count actual `recvmmsg`, `sendmmsg`, `sendmsg`, `recvmsg`, `read`, and `write` calls. Do not infer syscall reduction from an interface test.

### 14.5 Same-path AWG comparison

Use identical:

- client and gateway hardware
- NIC and link
- path MTU and inner MTU
- endpoint addresses
- route and firewall posture
- packet sizes and flow count
- test duration and warmup
- foreground/background and thermal state
- CPU affinity or scheduler policy
- download and upload directions

Test at least:

- iperf3 TCP with 1, 4, 8, and 32 streams
- iperf3 UDP at stepped offered load until loss or queue-delay limit
- 64-byte packets, 512-byte packets, and configured maximum inner packets
- 10-minute sustained maximum-load soak
- idle and burst transition
- ratchet under load
- migration and carrier fallback under load
- Android promotion and descriptor rebind
- Windows 100 start/stop cycles and long-TCP stall soak

Run at least 10 randomized back-to-back AWG/v3 pairs per platform and direction. Archive raw JSON, stdout, CPU, RSS, energy where available, packet/drop counters, syscalls, versions, and hashes.

## 15. Acceptance gates

### Gate A: correctness and equivalence

- All current unit tests pass.
- `go test -race` passes for core, session, carrier, driver, TUN, gateway, and cdatapath.
- `go vet` passes.
- `tools/verify_rulings.sh` passes.
- Existing KATs pass.
- At least one million randomized old/new Seal comparisons produce identical bytes for the same key, counter, payload, and padding.
- Old/new Open comparisons agree on valid, corrupt, truncated, replayed, reordered, and wrap-boundary inputs.
- A corrupt first copy never suppresses a later valid copy.
- No DATA crosses PQ, dual-auth, rekey, closing, or gate boundaries incorrectly.
- No nonce or demux token is reused for one key and epoch.
- No carrier failure causes resealing.

### Gate B: allocation and CPU

- Demux token: 0 B/op and 0 allocs/op.
- In-place Seal: 0 B/op and 0 allocs/op.
- In-place Open/OpenAt: 0 B/op and 0 allocs/op.
- DATA-only slot driver: 0 B/op and 0 allocs/op after startup.
- UDP batch send/receive: 0 B/op and 0 allocs/op after descriptor initialization.
- Full optimized path lowers median ns/packet by at least 25 percent before platform rollout.
- No untargeted microbenchmark median regression above 3 percent without an explained security tradeoff.

### Gate C: parallel scaling

- 2 workers: at least 1.7x one-worker packet throughput.
- 4 workers: at least 3.2x.
- 8 workers: at least 5.6x, where the platform has eight suitable cores.
- No ordering violation, replay double-delivery, epoch leak, or unexplained drop.
- p99 internal queue delay at or below 10 ms under the target load.
- Sustained queue occupancy below 75 percent.
- No one session can starve others at the gateway.

These are proposed engineering gates. Mobile targets may intentionally select fewer workers when energy or thermal limits dominate.

### Gate D: sustained component load

- Ten minutes at 100,000 maximum-size packets/s or the platform's measured line-rate packet load, whichever is lower for the first bring-up.
- Bursts through configured queue capacity.
- Zero unexplained packet loss.
- Named counters for every intentional drop.
- Clean cancellation with no leaked goroutine, fd, adapter, interface, or route.
- Linux proves batch size greater than one and lower syscalls/packet.
- Apple proves packet arrays greater than one in both directions.
- Windows records no receive stall above one second.
- Android records no unexpected TUN-reader termination and no unbounded allocation growth.

### Gate E: AWG parity

Product acceptance and parity are different claims.

Product acceptance floor:

- Every randomized pair retains at least 90 percent of AWG throughput.
- CPU-seconds/GiB and energy are no worse than 110 percent of AWG.

Parity claim:

- Geometric-mean v3/AWG throughput ratio is at least 1.00.
- Lower 95 percent confidence bound is at least 0.95.
- No valid pair is below 0.90.
- CPU-seconds/GiB is no worse than 105 percent of AWG.
- p99 added RTT is no worse than 10 percent or 5 ms, whichever is larger.
- No security, leak, teardown, or unexplained-drop regression.

Faster-than-AWG claim:

- Lower 95 percent confidence bound for v3/AWG throughput is greater than 1.00 on the named platform, direction, MTU, and workload.
- CPU and energy gates also pass.

A result from one platform or one packet size must be scoped to that case. It is not a protocol-wide claim.

## 16. Implementation plan

### Phase 0: freeze and fix correctness

1. Restore a complete Git checkout and record the exact SHA.
2. Install the local pre-push disclosure hook before any future push, per project policy.
3. Apply Patches 1 and 2.
4. Add the hostile same-plaintext state-transition tests.
5. Run targeted race, replay, ratchet, and gate suites.

Exit: Gate A passes on immutable source.

### Phase 1: measurement harness

1. Land the benchmark files and metric helper.
2. Add CPU, allocation, mutex, block, trace, and platform syscall capture scripts.
3. Record scalar baselines on every target.
4. Correct stale benchmark inventory in `winn_protocol_experimental/VERIFICATION.md:19-20`.

Exit: reproducible ten-sample baselines with raw artifacts and hashes.

### Phase 2: allocation-free core and ownership

1. Apply Patch 3 and prove token byte equivalence.
2. Apply Patch 4 as a compatibility improvement.
3. Add Patch 7 and slot-lifetime tests.
4. Add streaming frame parsing or `ParseFramesInto`.
5. Introduce bounded packet arenas and integer slot rings.
6. Add fast session methods that transfer slot ownership explicitly.
7. Keep allocating public wrappers.

Exit: Gate B core and DATA-only driver allocations pass.

### Phase 3: Linux socket batching

1. Apply the optional carrier interface from Patch 6.
2. Reuse the existing `internal/carrier` batch machinery.
3. Implement gateway shared-listener `ReadBatch` first.
4. Add the server-owned bounded send queue and successful-prefix accounting.
5. Replace packet-scoped cancellation callbacks with loop-scoped interruption.
6. Prove foreign-source filtering, partial batch, migration, and cancellation behavior.

Exit: actual Linux syscall/packet reduction with no wire difference.

### Phase 4: ordered multicore crypto

1. Add immutable per-epoch, per-worker AEAD/PRF keysets.
2. Make a single outbound sequencer reserve counters and sequences.
3. Add bounded worker queues and an ordered completion ring.
4. Split inbound verify from replay commit.
5. Shard duplicate counters to the same worker.
6. Add explicit ratchet barriers and keyset lifetime accounting.
7. Run corrupt-copy, duplicate, reorder, loss, wrap, ratchet, and migration stress under `-race`.

Exit: Gates A, B, and C pass.

### Phase 5: direct platform integrations

1. Linux: pass TUN fds to Go, then test 1/2/4/8 multiqueue.
2. Windows: remove loopback UDP and implement direct Wintun device.
3. Apple: land batch C ABI and preserve NetworkExtension arrays.
4. Android: fixed slot ring and fused framing, then JNI in-process engine.
5. Keep the scalar path behind a feature flag for rollback.

Exit: Gate D on real devices. Android also follows the required uninstall, release-APK install, launch, and logcat sequence.

### Phase 6: offloads and token-state acceleration

1. Add gateway-only `sendmmsg` and `recvmmsg` production rollout.
2. Add equal-size UDP GSO with packet-capture equivalence.
3. Add GRO OOB parsing and exact segmentation tests.
4. Benchmark precomputed SHA-256 chaining states against the allocation-free four-compression token function.
5. Add Linux TUN virtio headers only if the measured gain justifies the larger device contract.

Exit: no fallback, fingerprint, checksum, or datagram-boundary regression.

### Phase 7: AWG comparison and rollout

1. Run the randomized same-path comparison matrix.
2. Compute confidence intervals and pair-level floors.
3. Run leak, teardown, route, and censor/fallback tests.
4. Run final defensive review after bytes and artifacts are frozen.
5. Promote only the platforms that meet their named gates.

Exit: Gate E. Until then, the truthful status is "optimized v3 candidate, parity unverified."

## 17. Expected bottleneck progression

Removing one bottleneck changes the next one:

```text
today
heap allocation and GC
    => HMAC construction and map churn
    => driver serialization
    => per-packet UDP and TUN syscalls
    => platform bridge copies
    => ChaCha20-Poly1305 cycles
    => ordered-commit head-of-line delay
```

The order will differ by platform. Android is likely bridge/allocation-bound first. Windows is likely seam/syscall-bound before crypto. Linux gateway work should expose crypto and token cost earliest. Apple already receives arrays, so scalar ABI and `Data` copies are the immediate targets. These are source-based hypotheses and must be checked by the measurement harness.

## 18. Security properties that remain fixed

- Initial X25519 identity and key agreement remain unchanged.
- ML-KEM-768 ratchet remains unchanged and completes before strict-mode DATA.
- ChaCha20-Poly1305 remains the transport AEAD.
- Demux token bytes remain HMAC-SHA256 truncated to 8 bytes for v3.
- The token remains AEAD associated data.
- Failed authentication consumes no replay state.
- One authenticated message is delivered at most once.
- Old and new epochs do not share nonce/key pairs.
- Ratchets remain hard ordered cuts unless a separately reviewed grace design changes the protocol.
- Padding targets and carrier traffic-shape rules do not weaken for speed.
- TUN gate close remains a drain barrier.
- Handshake replay persistence remains durable before response.
- Migration never reseals already-numbered DATA.

## 19. Final engineering judgment

The current standalone v3 implementation is not slow because ML-KEM runs on every packet. It does not. The steady-state loss comes from ordinary systems costs: repeated packet allocation and copying, HMAC object creation, a pointer-heavy token map, one driver mutex across both directions, scalar UDP and TUN operations, and platform bridges that discard native batching.

The fastest safe route is not a new cipher or a weaker token. It is a WireGuard-shaped execution engine adapted to Winn's stricter state machine: preallocated packet ownership, sequential counter and state assignment, parallel stateless AEAD work, ordered replay/state commit, and platform-native I/O batches.

The largest early wins should come from allocation-free token/core work and removal of platform/process seams. Multicore crypto becomes valuable after those changes. GSO/GRO is a final multiplier on Linux, not the foundation.

The mission is feasible, but AWG parity is unverified. Claim parity only after the exact optimized artifacts beat the Gate E comparison on each named platform.

## 20. Primary external references

- [Go AEAD in-place contract](https://pkg.go.dev/crypto/cipher#AEAD)
- [Go garbage collector guide](https://go.dev/doc/gc-guide)
- [Go memory model](https://go.dev/ref/mem)
- [Go sync.Pool contract](https://pkg.go.dev/sync#Pool)
- [Go x/net IPv4 batch API](https://pkg.go.dev/golang.org/x/net/ipv4#PacketConn.ReadBatch)
- [Go x/net IPv6 batch API](https://pkg.go.dev/golang.org/x/net/ipv6#PacketConn.ReadBatch)
- [Official x/net batch implementation](https://go.googlesource.com/net/+/master/ipv4/batch.go)
- [wireguard-go outbound pipeline](https://git.zx2c4.com/wireguard-go/tree/device/send.go?id=ecfc5a8d5446)
- [wireguard-go worker creation](https://git.zx2c4.com/wireguard-go/tree/device/device.go?id=12269c276173)
- [AmneziaWG Go repository](https://github.com/amnezia-vpn/amneziawg-go)
- [Linux UDP segmentation and GRO API](https://man7.org/linux/man-pages/man7/udp.7.html)
- [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html)
- [Linux TUN/TAP multiqueue](https://docs.kernel.org/networking/tuntap.html)
- [Android VpnService](https://developer.android.com/reference/android/net/VpnService)
- [Android VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder)
- [Apple NEPacketTunnelFlow packet arrays](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets%28_%3Awithprotocols%3A%29)
- [Official Wintun API](https://github.com/WireGuard/wintun/blob/master/README.md)
- [NIST FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [RFC 8439 ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8)

