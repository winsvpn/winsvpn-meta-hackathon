# Stage 2 Rebuttal: stage2_fable51

# Podium 4 Cross-Rebuttal: Round 32, Stage 2

## 0. Ruling in six lines

Podium 1's 16 MB socket buffer change is a no-op on the handset. The kernel doubles after it clamps, so 8 MiB and 16 MiB requests produce the same `sk_rcvbuf`. Proof in 2.1.

Podium 2 wrote the only complete GSO and GRO code on the docket. It has three defects: a wrong cmsg width on receive, a buffer reuse race in the callback contract, and an EINVAL conflation that hides configuration errors behind a silent fallback.

Podium 3 made the sharpest framing argument and I concede part of my Stage 1 ceiling to it. Podium 3 also shipped a `ParcelFileDescriptor.adoptFd()` call that will close the live UDP socket at the next garbage collection, and a blocking TUN reader that cannot be stopped.

My own Stage 1 has a Kotlin `fcntl` that throws `EBADF` on every launch. Section 1 owns it.

On the Double VPN question: SNAT on `aicore` is required, policy routing is required, and neither is the expensive part. Per-packet netfilter traversal is. Section 6 replaces it with a flowtable.

No podium accounted for packet reordering when TUN writes fan out across threads. Section 7.3 fixes that for all four of us.

I have no tool access in this stage. Kernel constants and Android defaults below come from memory of source I have read; each one is tagged for Stage 3 verification where the claim is load-bearing.

---

## 1. Self-audit first

### 1.1 My wire ceiling used the wrong frame size

Stage 1, Section 1.2: I charged every tunnel packet 1538 wire bytes and derived 162,548 pps and a 1.733 Gbps goodput ceiling. That charge is only correct if the outer datagram is a full 1500 bytes, which means 127 bytes of overhead above a 1373 inner MTU.

Opus 5 assumed 32 bytes of Winn v3 framing and got an outer datagram of 1433 bytes, 1471 on the wire, 169,952 pps, 1,812.6 Mbps.

The docket never states the Winn v3 header layout. That single unknown is why the council produced three ceilings (1.73, 1.81, 1.87 Gbps). Here is the honest position: if framing is 32 bytes, Opus is right and I concede 1,812.6 Mbps as the inner TCP ceiling. If framing is around 127 bytes, my 1.733 stands.

One piece of evidence favors the larger overhead. Nobody chooses 1373 when 1440 fits. Either the framing is fatter than 32 bytes, or the inner MTU was set against a path smaller than 1500 (PPPoE at 1492, or an IPv6 outer), or it was picked empirically without derivation. Stage 3 must produce the byte-exact header layout before anyone quotes a ceiling again.

### 1.2 My ChaCha20-Poly1305 throughput was optimistic

I claimed 1.5 to 2.5 GB/s per core citing "the arm64 assembly in `golang.org/x/crypto`". Opus is correct that only half of that AEAD has arm64 assembly. `chacha20` has `chacha_arm64.s`. `internal/poly1305` ships `sum_amd64.s`, `sum_ppc64x.s`, `sum_s390x.s`, and generic Go elsewhere. On arm64 the MAC runs through `math/bits.Mul64`, which compiles to `MUL` plus `UMULH`, so it is not slow, but it is not NEON either. Combined AEAD throughput lands nearer 1.0 to 1.5 GB/s on an Oryon-class core.

At 250 MB/s per direction that is 17 to 25 percent of a core, not the 10 to 17 percent I stated. Conclusion unchanged: crypto is not the serialized per-packet bottleneck. The syscall path is. But the margin is thinner than I implied, and Opus's AEAD negotiation proposal (Section 4.3) is worth adopting.

### 1.3 My Kotlin fcntl line is broken

```kotlin
Os.fcntlInt(
    ParcelFileDescriptor.adoptFd(tunFd).also { it.detachFd() }.fileDescriptor,
    OsConstants.F_SETFL,
    OsConstants.O_NONBLOCK
)
```

`detachFd()` calls `Parcel.clearFileDescriptor(mFd)` and sets the internal descriptor to `-1` before returning. The `.fileDescriptor` accessed afterwards wraps `-1`. `Os.fcntlInt` throws `ErrnoException(EBADF)`. Delete the line. My Go `NewTUN` already calls `unix.SetNonblock(fd, true)`, which is the correct place for it.

### 1.4 Reordering

My Stage 1 argued that N TUN writer threads spread `netif_rx` across N CPUs. True. It also reorders packets within a single inner flow whenever two writers hold consecutive segments of the same TCP stream. Linux TCP tolerates reordering via RACK, but every reordering event costs the inner stack a DSACK exchange and can trigger spurious retransmits at the sender. Fix in 7.3: shard by inner 5-tuple hash, one ring per writer, so a flow never crosses threads. Opus's multi-thread proposal has the same gap.

---

## 2. Audit of Podium 1 (Antigravity)

### 2.1 The 16 MB buffer change does nothing on the handset

`sock_setsockopt` for `SO_RCVBUF`:

```c
val = min_t(u32, val, READ_ONCE(sysctl_rmem_max));
sk->sk_rcvbuf = max_t(int, val * 2, SOCK_MIN_RCVBUF);
```

Clamp first, then double. AOSP's `init.rc` writes `8388608` to both `net.core.rmem_max` and `net.core.wmem_max` on every device I have inspected, and Samsung's kernel inherits it (Stage 3: `adb shell cat /proc/sys/net/core/rmem_max`). Two requests:

- Request 8 MiB: clamp to 8 MiB, double, `sk_rcvbuf = 16,777,216`.
- Request 16 MiB: clamp to 8 MiB, double, `sk_rcvbuf = 16,777,216`.

Identical. `getsockopt` reports 16,777,216 in both cases. The change Podium 1 headlined as "complete absorption headroom" alters zero bytes of kernel state. `SO_RCVBUFFORCE` bypasses the clamp but needs `CAP_NET_ADMIN`, which an app does not have.

The 40 ms stall figure is asserted, not measured. Sol Pro's point stands: the existing allocation already covers 33 ms of payload at 2 Gbps (and the kernel accounts `truesize`, so real payload capacity is roughly half the reported value; still 30 ms plus).

There is a real buffer hazard, and it is on `aicore`, not the handset. Stock Linux `rmem_max` is 212,992 bytes. Unless someone raised it, every 8 MB or 16 MB request from the Winn daemon on `aicore` clamps to 208 KiB and doubles to 416 KiB. At 2 Gbps that is 1.7 ms of absorption. Check `nstat -az UdpRcvbufErrors` on `aicore`. The engine's "0 dropped" counter cannot see kernel-side socket drops; Sol Pro was right to flag that distinction.

```bash
# aicore
sysctl -w net.core.rmem_max=67108864
sysctl -w net.core.wmem_max=67108864
```

Or use `SO_RCVBUFFORCE` from the daemon, which runs as root.

### 2.2 GSO and GRO deployed on the wrong halves

Podium 1 puts GSO on the handset uplink and GRO on the gateway downlink. Both accelerate handset upload. Neither touches handset download, which is the headline metric and where the server transmits. Sol Pro caught this precisely: transmit batching for download happens on `aicore`, receive coalescing for download happens on the handset. All four combinations are needed. Concession to Podium 2.

### 2.3 The 1402 byte datagram is not derivable

Podium 1 states framing is "1 byte tag + 16 bytes auth/IV = 17 bytes minimum", then describes "45 individual 1402-byte UDP wire datagrams". 1373 + 17 = 1390. 1373 + 32 = 1405. No stated framing produces 1402. Internal inconsistency, and it matters because the GSO `segmentSize` must equal the exact encrypted record length or the kernel emits wrong datagrams.

Also: "delegates it directly to the NIC hardware segmentation offload." Wi-Fi drivers do not advertise `NETIF_F_GSO_UDP_L4`. On the handset, `__udp_gso_segment` runs in software. That still saves the syscalls, which is the entire point, but the hardware claim is false.

### 2.4 Nested versus terminated: the MTU section is built on the wrong model

Section 3.2: "If Hop 2 encapsulates inside Hop 1, the inner MSS must account for the secondary WireGuard/Winn header (32 to 80 bytes)."

It does not encapsulate inside Hop 1. The docket says Double VPN is "via aicore 1st Hop". Hop 1 terminates on `aicore`. The decrypted inner IP packet is forwarded, then Hop 2 encrypts it fresh toward Canada or Kansas. Each hop pays its own overhead against its own physical path. Overheads do not add. Set the `aicore` exit tunnel MTU to 1373 (or to whatever the handset's inner MTU is) and there is nothing to clamp beyond 1333 for IPv4 inner and 1313 for IPv6 inner. The "93 bytes wasted at 1240" argument fights a problem that only exists under client-side onion nesting.

### 2.5 The forwarding ruleset never matches

```bash
iptables -A FORWARD -i winn3gw0 -o tun_exit -j ACCEPT
iptables -t nat -A POSTROUTING -o tun_exit -j MASQUERADE
```

Nothing in Section 3.3 routes handset traffic into `tun_exit`. The main table's default route points at the WAN. Forwarded packets from `winn3gw0` follow it out the WAN interface, the `-o tun_exit` rules never fire, and the "Double VPN" degrades silently to a single hop with `aicore` as the exit. You need an `ip rule` keyed on source or fwmark. Section 6 provides it.

Second omission: `rp_filter`. Reply packets for public sources arrive on `tun_exit`, but the reverse route for those sources is the WAN. With strict reverse path filtering (`rp_filter=1`, common on Debian and Ubuntu derived hosts) the kernel drops every reply. Set `rp_filter=2` on the exit interfaces or enable `src_valid_mark`.

Third: `-m state` has been an alias for `-m conntrack --ctstate` for a decade. Minor, but it signals the ruleset was not run.

### 2.6 FQ on a forwarding interface

`fq` paces using `sk->sk_pacing_rate` from a local TCP socket. Forwarded packets have no socket. On `winn3gw0` in Double VPN mode, `fq` degrades to a hashed FIFO with 32,768 slots and no pacing. If you want a qdisc there, `fq_codel` or `cake` handles ownerless flows properly. The actual queue that matters on a tun device is the `ptr_ring` sized by `txqueuelen`, default 500, which is 3 ms at 170 kpps. Raise it: `ip link set dev winn3gw0 txqueuelen 10000`. That one change does more than any qdisc.

### 2.7 Wake locks do not control clocks

`PARTIAL_WAKE_LOCK` prevents suspend. It does not prevent DVFS from parking the datapath threads on a little core at 1 GHz. The lever for that is ADPF: `PerformanceHintManager.createHintSession(tids, targetNanos)` with `reportActualWorkDuration` per batch, available since API 31 and honored by Samsung's scheduler since One UI 5. Feed it the datapath thread ids from Go (`unix.Gettid()` under `LockOSThread`).

### 2.8 Syscall accounting

182,083 pps is inner bytes at 2 Gbps, which by every podium's arithmetic is unreachable. The count also treats TUN write and UDP receive as equal-cost 1.2 microsecond crossings. A TUN write allocates an skb, copies, and runs `netif_rx`; it is two to three times heavier than a UDP `recvmsg`. Direction of the argument is right. Numbers are not.

---

## 3. Audit of Podium 2 (Sol Pro)

The math sections are the cleanest on the docket. The bandwidth delay product argument, the full duplex gain requirement, and the double VPN bound `min(T_hop1, T_hop2, T_crypto, T_packet)` are all correct. Two objections and a code review.

### 3.1 The serialized double VPN bound is too pessimistic

`T_double = F / (c1 + c2)` assumes both crypto stages share one core pool at saturation. On `aicore`, a server with many cores, Hop 1 decryption and Hop 2 encryption run on different threads trivially. The real double VPN cost is not crypto. It is the kernel forwarding path between them: a TUN write into `winn3gw0`, an IP forward with netfilter traversal, a TUN read from the exit tunnel. Opus's 2.9 microsecond estimate for that round trip is plausible and I share it. Section 6 gives a two-command reduction.

### 3.2 Code review of `udpoffload_linux.go`

Line by line, what is right first.

`udpSegment = 103` and `udpGRO = 104`: correct values. `golang.org/x/sys/unix` already exports `UDP_SEGMENT` and `UDP_GRO`, so the literals are redundant but harmless.

`makeGSOCmsg`: `CmsgSpace(2)`, `CmsgLen(2)`, `__u16` payload. Correct. `udp_cmsg_send` rejects any `cmsg_len` other than `CMSG_LEN(sizeof(__u16))`, and this satisfies it.

Now the defects.

**Defect 1: GRO cmsg width.** `ReadGRO` parses `binary.NativeEndian.Uint16(msg.Data[:2])`. The kernel emits the segment size via `put_cmsg(msg, SOL_UDP, UDP_GRO, sizeof(int), &gso_size)`. Four bytes. On little-endian arm64 the low two bytes carry the value, so this works by accident. On any big-endian target it reads zero and every aggregate is misparsed as a single 65 KB datagram, which then fails AEAD authentication. Opus flagged the two-out, four-in asymmetry correctly. Read `Uint32(msg.Data[:4])`.

**Defect 2: the callback contract is a use-after-reuse race.** `ReadGRO` hands `data[offset:end]` to `consume` synchronously and then the caller's loop reuses `rxData` on the next `ReadMsgUDP`. If `consume` pushes the slice into a ring for a TUN writer thread (which is the whole architecture), the writer reads bytes that the next `recvmsg` is overwriting. Either `consume` must copy (an extra 1.4 KB memcpy per packet, roughly 0.15 us), or the slab must be refcounted and rotated. Section 7.2 does the latter.

**Defect 3: EINVAL is not "unsupported".** `IsGSOUnsupported` treats `EINVAL` as a signal to fall back to per-packet writes. The kernel returns `EINVAL` from `udp_send_skb` for at least three other reasons: `gso_size` plus headers exceeds the route MTU, payload exceeds `gso_size * UDP_MAX_SEGMENTS`, or `sk_no_check_tx` is set. Every one of those is a bug in the caller. The fallback hides them and the metrics show a slow but "working" system. Probe GSO once at socket setup with a two-segment test datagram to loopback, cache the boolean, and treat `EINVAL` during operation as fatal.

**Defect 4: the 64 segment ceiling.** `UDP_MAX_SEGMENTS` was `1 << 6` (64) for years. Recent kernels define it as `1 << 7` (128). Stage 3 must check `include/linux/udp.h` for the `aicore` kernel. 64 is the correct portable floor; for full-size records it does not bind anyway (65507 / 1433 = 45). It binds hard for small records: with 84 byte ACK-carrying records, 64 segments is 5.4 KB per syscall instead of 65 KB. Probe and use the larger limit when available.

**Defect 5: no batching logic.** The comment says "Every record except the last must have segmentSize bytes." Correct kernel requirement. Nothing in the submission groups records by size. Real traffic is bimodal: full-size data one way, small ACKs the other. A batcher that flushes on every size change, with a one-record lookahead so a lone odd-size packet at the tail can ride as the final segment, is required. Section 7.1.

### 3.3 The SPSC ring and goroutine parking

The ring code itself was cut from the docket text I received, so this evaluates the design constraints Sol Pro's architecture implies, and the mandate's specific question.

First, "heavy TUN write backpressure" does not exist as a blocking signal. `tun_get_user` never returns `EAGAIN`. It allocates, copies, and calls `netif_rx`, which enqueues to the per-CPU backlog; when that backlog exceeds `netdev_max_backlog` (default 1000) the kernel drops silently and increments column two of `/proc/net/softnet_stat`, which Android's SELinux policy hides from apps. The ring between the UDP reader and the TUN writer will never fill because TUN is slow. It fills only when the writer thread is descheduled. So the parking question reduces to correctness on the empty side, not the full side.

On the empty side, the classic bug is the lost wakeup: consumer checks the ring (empty), producer publishes and checks a "parked" flag (still zero), consumer sets the flag and sleeps forever. The fix is a Dekker-style protocol using sequentially consistent atomics, which Go's `sync/atomic` provides: consumer stores `waiting=1` then re-reads tail; producer stores tail then swaps `waiting`. Any interleaving either lets the consumer see the new tail or lets the producer see `waiting=1`. Section 7.3 has the code and the proof sketch.

Second constraint: SPSC is the wrong shape if there are N TUN writers. Either N rings (one per writer, sharded by flow hash) or one MPMC ring. N rings is faster and preserves per-flow ordering. Use that.

Upload direction is the mirror: TUN readers park on empty via `poll()` (my Stage 1 design), and the backpressure signal is UDP `sendmsg` blocking or `EAGAIN` on a full send buffer, which is real and must be handled with `POLLOUT`.

---

## 4. Audit of Podium 3 (Opus 5)

### 4.1 Framing ceiling: conditional concession

Covered in 1.1. Opus's derivation is internally correct. Whether it applies depends on a 32 byte framing assumption the docket does not confirm.

### 4.2 Inner MTU 1440 is a PMTU gamble

Section 1.3 recommends inner MTU 1440 on Single VPN so the outer datagram is exactly 1500. That holds only for an IPv4 outer over a path with a full 1500 MTU. Two common conditions break it: an IPv6 outer (1440 + 32 + 8 + 40 = 1520) and PPPoE fiber (1492). Either produces outer UDP fragmentation or DF drops on every full-size packet. The 4.36 percent frame rate reduction is real, and worth having, but only behind a PMTU probe at session establish. Never static.

Also, "you cannot take it on Double VPN" is only true under the nested model. Terminated hops are independent. If both paths support it, both hops run at 1440.

### 4.3 AEAD negotiation: accept

The x/crypto assembly facts are correct (see 1.2). Go's `crypto/aes` on arm64 uses `AESE`/`AESMC` and `PMULL` through `gcm_arm64.s`; 3 to 5 GB/s per core is the right neighborhood. The benchmark harness is sound and the "measure before committing" gate is the correct discipline. One addition: if the negotiation lands, the nonce schedule for a 96 bit GCM nonce needs the same never-repeat guarantee the ChaCha path already has, and the 2^32 record limit per key on AES-GCM is reached in about 6.5 hours at 182 kpps. Rekey on record count, not just on time.

### 4.4 The blocking TUN reader cannot be stopped

`AttachTun` sets both descriptors blocking and dedicates OS threads. Consider shutdown. A thread parked in `read()` on a tun descriptor sleeps in `tun_ring_recv`, which wakes on a packet, a signal, or `RCV_SHUTDOWN` on the tun socket. `close()` from another thread does none of those: the reader holds a reference to the `struct file`, so the close is deferred until the read returns. `RCV_SHUTDOWN` is set in `tun_detach_all`, which runs when the netdevice unregisters, which happens only after the last descriptor closes, which cannot happen while the reader holds it. Circular.

Signals do not help from Go. The runtime installs handlers with `SA_RESTART`, so `unix.Read` restarts transparently after the handler returns. There is no `pthread_kill` escape hatch available to portable Go code.

Net effect: after `stop()`, the reader thread hangs until some app on the device emits a packet into the dead tunnel. Usually seconds. Sometimes much longer with the screen off. Then `onRevoke()` from a competing VPN app produces the same hang. Nonblocking plus `poll()` with an `eventfd` cancel (my Stage 1 `TUN.Read`) is the correct shape. Under load the `poll()` path is almost never taken because `read()` succeeds immediately; the cost argument against it is negligible.

### 4.5 The dup rationale is void

"Duplicating gives each direction its own thread without contention on the file position lock." `dup()` shares the same `struct file`, including any position lock. The tun character device opens with `nonseekable_open`, so `FMODE_ATOMIC_POS` is never set and there is no position lock to contend. The dup is harmless. The reason given for it is wrong. Reads and writes on one tun descriptor from two threads were already independent.

### 4.6 `adoptFd` closes the outer socket

```kotlin
runCatching { it.bindSocket(ParcelFileDescriptor.adoptFd(fd).fileDescriptor) }
```

`ParcelFileDescriptor.adoptFd(int)` takes ownership. Its `Cleaner` closes the descriptor when the object becomes unreachable, which is immediately after this expression. At the next garbage collection the Go engine's connected UDP socket is closed under it. Every subsequent `sendmsg` returns `EBADF`. Intermittent, GC-timed, brutal to debug. Use `ParcelFileDescriptor.fromFd(fd)` (which dups) and close the wrapper explicitly, or build a `FileDescriptor` via `Os.dup` and `Os.close` it after binding.

### 4.7 `activeNetwork` after `establish()` may be the VPN itself

`setUnderlyingNetworks(arrayOf(cm.activeNetwork))` runs after `establish()`. For the VPN app's own UID, the default network becomes the VPN network as soon as it connects. There is a race window where `activeNetwork` returns the tunnel, and the tunnel is then declared as its own underlying transport. Resolve the physical network before `establish()`, or better, register a `NetworkCallback` with a `NetworkRequest` requiring `TRANSPORT_WIFI` and `NET_CAPABILITY_NOT_VPN`, and re-pin on every `onAvailable`.

### 4.8 Finding B: accept and sharpen

SpeedBench at 1,345 Mbps against `aicore` at 192.168.4.36 is a LAN measurement. That is exactly the right instrument for the handset engine ceiling, which is what Round 32 optimizes. It is the wrong instrument for any claim about the 2 Gbps fiber, and the Ookla 637 Mbps figure is the only WAN data point on the docket. Both numbers should be reported, labeled, and never conflated again.

### 4.9 The cost table

Opus puts a TUN write at 1.20 us. I put it at 3 to 4 us. Neither of us measured it on this handset. The disagreement is 2 to 3 us per packet, which is the entire gap between "we hit the ceiling" and "we do not". Resolve it with `simpleperf record -e cpu-clock --call-graph fp -p <pid>` on a `profileable` build, which Android permits for the app's own process. Until then both tables are hypotheses.

---

## 5. Descriptor lifecycle ruling: `detachFd()` versus `dup()` versus SCM_RIGHTS

Three options, one answer.

**`detachFd()`**: ownership moves to Go, Kotlin's `ParcelFileDescriptor` is marked closed and will never touch the descriptor again. Go must close on `stop()` and on `onRevoke()`. The interface tears down when Go's close is the last reference. Clean single owner. This is the answer for an in-process gomobile engine.

**`dup()` (via `ParcelFileDescriptor.dup()` or `Os.dup`)**: two owners. The interface stays alive until both close. If Go forgets, Kotlin's close is silent and the tunnel lingers with a dead engine behind it: traffic blackholes instead of failing over. If Kotlin forgets, the leaked descriptor keeps `netd`'s interface alive across engine restarts. Use only if some Kotlin code path must retain a handle, and then document which side owns teardown. Note that `F_SETFL` on either descriptor changes the shared open file description; the two sides can fight over `O_NONBLOCK`.

**SCM_RIGHTS over an `AF_UNIX` socket**: correct when the engine is a separate process (memory isolation, crash containment). Costs one socketpair at establish and nothing per packet, so it is not the old LocalSocket relay and should not be confused with it. It is pointless when Go is loaded into the app process, which is the case here.

Verdict: `detachFd()`, Go owns, `onRevoke()` calls `Engine.stop()` which closes the tun descriptor and the outer socket in that order. Sol Pro's `SO_RXQ_OVFL` counter and my `eventfd` cancel both survive this model unchanged.

---

## 6. Double VPN on `aicore`: SNAT, policy routing, and the fast path

### 6.1 Is MASQUERADE required?

Yes, unless Winn v3 supports prefix delegation. Reasoning:

The handset's inner source is 10.10.0.14. After Hop 1 terminates, that packet is forwarded into the Hop 2 session toward Canada ca1 (<NODE_CANADA_IP>). Two things happen at ca1. First, any well-built tunnel protocol validates the inner source against the addresses assigned to that session (WireGuard calls this cryptokey routing; Winn v3 presumably has an equivalent, otherwise any client can spoof any other). A packet from 10.10.0.14 arriving on a session whose assigned address is, say, 10.21.0.2 gets dropped as spoofed. Second, even if ca1 forwards it, the reply must be routed back to 10.10.0.14, and ca1 has no route for that prefix pointing into `aicore`'s session.

Pure policy routing on `aicore` fixes neither. Both require control-plane changes on ca1, de1, es1, and Kansas Core: route injection for 10.10.0.0/24 via `aicore`'s session and disabling source validation for that session. Four gateways, one config each, plus a protocol extension.

SNAT to `aicore`'s own Hop 2 inner address fixes both with zero changes on the exits. Every exit sees one ordinary single-client session.

On cost: I want to correct a claim I was about to make and that appears in folklore. `MASQUERADE` does not re-evaluate the source address per packet. It selects the outgoing interface's address when the conntrack entry is created and flushes entries when the interface goes down. Its per-packet cost equals `SNAT`. Use `masquerade` if the exit tunnel addresses change on reconnect, `snat to` if they are stable. Either way the NAT lookup is not the expensive part.

### 6.2 Is policy routing required?

Also yes. Four exits means four default routes, selected per client (or per client policy). The main table keeps `aicore`'s own default via WAN. Each client's traffic gets an fwmark at ingress on `winn3gw0` and a dedicated table.

### 6.3 What is actually expensive

Every forwarded packet at 170 kpps traverses the full netfilter hook chain: conntrack lookup, mangle, filter, nat. A software flowtable moves established flows to an ingress hook fast path that does the conntrack lookup, applies NAT, and transmits, skipping the rest. Kernels since 4.16 support NAT in flowtables; software flowtables work on any device including tun. This is the "zero-copy kernel forwarding" Podium 1 named but did not provide.

### 6.4 Complete `aicore` configuration

```bash
# /etc/sysctl.d/90-winn-relay.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.fib_multipath_use_neigh = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 16384
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
```

```bash
# Interfaces: winn3gw0 (hop 1 ingress, 10.10.0.1/24)
#             wx_ks1, wx_ca1, wx_de1, wx_es1 (hop 2 egress tunnels, MTU 1373)
for dev in winn3gw0 wx_ks1 wx_ca1 wx_de1 wx_es1; do
  ip link set dev "$dev" mtu 1373
  ip link set dev "$dev" txqueuelen 10000
done

# Policy routing tables: one per exit
ip route replace default dev wx_ks1 table 101
ip route replace default dev wx_ca1 table 102
ip route replace default dev wx_de1 table 103
ip route replace default dev wx_es1 table 104

ip rule add fwmark 0x101 lookup 101 pref 1101
ip rule add fwmark 0x102 lookup 102 pref 1102
ip rule add fwmark 0x103 lookup 103 pref 1103
ip rule add fwmark 0x104 lookup 104 pref 1104
```

```nft
# /etc/nftables.d/winn-relay.nft
table inet winn_relay {

    # Client to exit assignment. Populated by the session daemon.
    map client_exit {
        type ipv4_addr : mark
        elements = { 10.10.0.14 : 0x102 }
    }

    flowtable ft {
        hook ingress priority filter
        devices = { winn3gw0, wx_ks1, wx_ca1, wx_de1, wx_es1 }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "winn3gw0" meta mark set ip saddr map @client_exit
        # Replies need the same mark so rp_filter with src_valid_mark agrees.
        iifname { "wx_ks1", "wx_ca1", "wx_de1", "wx_es1" } ct mark != 0 meta mark set ct mark
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        ct state established,related flow add @ft
        ct state established,related accept

        iifname "winn3gw0" oifname { "wx_ks1", "wx_ca1", "wx_de1", "wx_es1" } \
            tcp flags syn tcp option maxseg size set rt mtu
        iifname "winn3gw0" oifname { "wx_ks1", "wx_ca1", "wx_de1", "wx_es1" } \
            ct state new ct mark set meta mark accept
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname { "wx_ks1", "wx_ca1", "wx_de1", "wx_es1" } masquerade
    }
}
```

`tcp option maxseg size set rt mtu` clamps to the outgoing route MTU minus headers: 1333 for IPv4 inner, 1313 for IPv6 inner. With both tunnels at 1373 it is belt and braces; the handset's own TCP already advertises 1333 because `VpnService.Builder.setMtu(1373)` governs its MSS. It matters for the SYN-ACK direction and for any future exit tunnel with a smaller MTU.

The flowtable path is the interim answer. The principled answer remains the in-process userspace crossover Opus and I both proposed, where the Winn daemon holds both sessions and re-encrypts without ever writing to a tun device. That is a protocol daemon change and belongs in Round 33.

---

## 7. Hardened code

### 7.1 GSO batcher with size grouping, single-shot probe, and honest error handling

```go
//go:build linux

package datapath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	maxUDPPayload      = 65507
	portableMaxSegs    = 64  // UDP_MAX_SEGMENTS floor on every supported kernel
	extendedMaxSegs    = 128 // recent kernels; enabled only if the probe accepts it
	gsoSlabBytes       = 65536
)

// GSOWriter accumulates independently encrypted records of identical length
// and emits them as one UDP_SEGMENT sendmsg. A record whose length differs
// from the current run flushes the run first, unless it is the only remaining
// record, in which case it rides as the legal shorter final segment.
type GSOWriter struct {
	conn    *net.UDPConn
	slab    []byte
	used    int
	segSize int
	count   int
	maxSegs int
	enabled bool
	oob     [unix.CmsgSpace(2)]byte
}

func NewGSOWriter(conn *net.UDPConn) (*GSOWriter, error) {
	w := &GSOWriter{
		conn:    conn,
		slab:    make([]byte, gsoSlabBytes),
		maxSegs: portableMaxSegs,
	}
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&w.oob[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))

	enabled, ext, err := probeGSO(conn)
	if err != nil {
		return nil, err
	}
	w.enabled = enabled
	if ext {
		w.maxSegs = extendedMaxSegs
	}
	return w, nil
}

// probeGSO sends two small segments to the connected peer with UDP_SEGMENT.
// ENOPROTOOPT or EOPNOTSUPP mean the kernel lacks the option. EINVAL here,
// with a tiny gso_size and two segments, also means unsupported (old kernels
// return it from udp_cmsg_send). During normal operation EINVAL is fatal.
func probeGSO(conn *net.UDPConn) (enabled bool, extended bool, err error) {
	var oob [unix.CmsgSpace(2)]byte
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], 8)

	probe := make([]byte, 16) // two 8 byte segments; peer discards them as malformed records
	_, _, werr := conn.WriteMsgUDP(probe, oob[:], nil)
	switch {
	case werr == nil:
	case errors.Is(werr, unix.ENOPROTOOPT),
		errors.Is(werr, unix.EOPNOTSUPP),
		errors.Is(werr, unix.EINVAL):
		return false, false, nil
	default:
		return false, false, fmt.Errorf("gso probe: %w", werr)
	}

	// Probe the segment ceiling: 65 segments of 8 bytes. EINVAL means the
	// kernel still enforces 64.
	probe = make([]byte, 8*65)
	_, _, werr = conn.WriteMsgUDP(probe, oob[:], nil)
	if werr == nil {
		return true, true, nil
	}
	if errors.Is(werr, unix.EINVAL) {
		return true, false, nil
	}
	return false, false, fmt.Errorf("gso segment probe: %w", werr)
}

// Push copies one encrypted record into the slab. It flushes automatically
// when the run is full, when the payload cap is reached, or when the record
// length differs from the run and the run is nonempty.
func (w *GSOWriter) Push(rec []byte) error {
	if !w.enabled {
		_, err := w.conn.Write(rec)
		return err
	}
	if w.count > 0 && len(rec) != w.segSize {
		// A shorter record may close the run as the final segment.
		if len(rec) < w.segSize && w.count < w.maxSegs && w.used+len(rec) <= maxUDPPayload {
			copy(w.slab[w.used:], rec)
			w.used += len(rec)
			w.count++
			return w.Flush()
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	if w.count == 0 {
		w.segSize = len(rec)
	}
	copy(w.slab[w.used:], rec)
	w.used += len(rec)
	w.count++
	if w.count >= w.maxSegs || w.used+w.segSize > maxUDPPayload {
		return w.Flush()
	}
	return nil
}

// Flush emits the accumulated run. Errors are returned unfiltered: an EINVAL
// during operation is a caller bug (segment plus headers over MTU, or over
// the segment cap) and must surface, not degrade.
func (w *GSOWriter) Flush() error {
	if w.count == 0 {
		return nil
	}
	defer func() { w.used, w.count = 0, 0 }()

	if w.count == 1 {
		_, err := w.conn.Write(w.slab[:w.used])
		return err
	}
	binary.NativeEndian.PutUint16(w.oob[unix.CmsgLen(0):], uint16(w.segSize))
	n, _, err := w.conn.WriteMsgUDP(w.slab[:w.used], w.oob[:], nil)
	if err != nil {
		return fmt.Errorf("gso flush seg=%d count=%d: %w", w.segSize, w.count, err)
	}
	if n != w.used {
		return fmt.Errorf("gso flush short write %d of %d", n, w.used)
	}
	return nil
}
```

The probe datagrams reach the peer as two or sixty-five 8 byte records. Any AEAD record parser rejects them. If the peer logs auth failures, whitelist an 8 byte length as a probe marker. Alternatively, probe against a loopback socket before connecting; that requires a second socket and is the cleaner choice on `aicore`. On the handset, loopback is fine too since `protect()` does not affect 127.0.0.1.

### 7.2 GRO reader with correct cmsg width and refcounted slabs

```go
//go:build linux

package datapath

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Slab is one recvmsg worth of bytes. Segments referencing it hold a count;
// the slab returns to the pool when the last segment is released.
type Slab struct {
	buf  []byte
	refs atomic.Int32
	pool *sync.Pool
}

func (s *Slab) release() {
	if s.refs.Add(-1) == 0 {
		s.pool.Put(s)
	}
}

// Segment is one encrypted record inside a Slab.
type Segment struct {
	Data []byte
	slab *Slab
}

func (g Segment) Release() { g.slab.release() }

type GROReader struct {
	conn        *net.UDPConn
	pool        sync.Pool
	oob         []byte
	SocketDrops atomic.Uint64
	Aggregates  atomic.Uint64
	Segments    atomic.Uint64
}

func NewGROReader(conn *net.UDPConn) (*GROReader, error) {
	r := &GROReader{conn: conn, oob: make([]byte, 256)}
	r.pool.New = func() any {
		return &Slab{buf: make([]byte, 65535), pool: &r.pool}
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1); e != nil {
			serr = e
			return
		}
		// UDP_GRO failing is acceptable; the reader then sees one record per call.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		return nil, err
	}
	return r, serr
}

// ReadBatch performs one recvmsg and appends each record to out.
// Callers must Release every Segment once its bytes are no longer needed.
func (r *GROReader) ReadBatch(out []Segment) ([]Segment, error) {
	slab := r.pool.Get().(*Slab)
	n, oobn, flags, _, err := r.conn.ReadMsgUDP(slab.buf, r.oob)
	if err != nil {
		r.pool.Put(slab)
		return out, err
	}
	if flags&unix.MSG_TRUNC != 0 {
		r.pool.Put(slab)
		return out, fmt.Errorf("gro: payload truncated at %d bytes", n)
	}

	segSize := 0
	if oobn > 0 {
		msgs, perr := unix.ParseSocketControlMessage(r.oob[:oobn])
		if perr != nil {
			r.pool.Put(slab)
			return out, perr
		}
		for _, m := range msgs {
			switch {
			case m.Header.Level == unix.SOL_UDP && m.Header.Type == unix.UDP_GRO:
				// Kernel emits sizeof(int) here. Four bytes, not two.
				if len(m.Data) >= 4 {
					segSize = int(binary.NativeEndian.Uint32(m.Data[:4]))
				}
			case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SO_RXQ_OVFL:
				if len(m.Data) >= 4 {
					r.SocketDrops.Store(uint64(binary.NativeEndian.Uint32(m.Data[:4])))
				}
			}
		}
	}

	if segSize <= 0 || segSize >= n {
		slab.refs.Store(1)
		r.Segments.Add(1)
		return append(out, Segment{Data: slab.buf[:n], slab: slab}), nil
	}

	count := (n + segSize - 1) / segSize
	slab.refs.Store(int32(count))
	r.Aggregates.Add(1)
	r.Segments.Add(uint64(count))
	for off := 0; off < n; off += segSize {
		end := off + segSize
		if end > n {
			end = n
		}
		out = append(out, Segment{Data: slab.buf[off:end], slab: slab})
	}
	return out, nil
}
```

Telemetry is not optional here. `Segments / Aggregates` is the observed coalescing ratio. If it sits near 1.0 on the handset under a saturating download, the Wi-Fi driver is delivering through `netif_receive_skb` rather than `napi_gro_receive` and `UDP_GRO` is doing nothing. Then fall back to `recvmmsg` with 32 vectors via `unix.Syscall6(unix.SYS_RECVMMSG, ...)` (x/sys/unix has no wrapper; wireguard-go's `conn/` package shows the pattern). Qualcomm's `qcacld-3.0` driver on this handset has a `gro_enable` ini knob and a NAPI path; whether Samsung shipped it enabled is a measurement, not an assumption.

### 7.3 Ring with proven parking, sharded by flow

```go
package datapath

import (
	"hash/maphash"
	"runtime"
	"sync/atomic"
)

// Ring is single producer, single consumer. One instance per TUN writer thread.
type Ring struct {
	buf     []Segment
	mask    uint64
	head    atomic.Uint64 // consumer index
	tail    atomic.Uint64 // producer index
	waiting atomic.Uint32
	wake    chan struct{}
}

func NewRing(sizePow2 int) *Ring {
	if sizePow2&(sizePow2-1) != 0 {
		panic("ring size must be a power of two")
	}
	return &Ring{
		buf:  make([]Segment, sizePow2),
		mask: uint64(sizePow2 - 1),
		wake: make(chan struct{}, 1),
	}
}

// Push returns false when full. Caller drops (and Releases) the segment;
// the inner TCP flow sees loss and backs off, which is the correct signal.
func (r *Ring) Push(s Segment) bool {
	t := r.tail.Load()
	if t-r.head.Load() == uint64(len(r.buf)) {
		return false
	}
	r.buf[t&r.mask] = s
	r.tail.Store(t + 1)
	// Publish before checking the flag. Sequentially consistent atomics make
	// this store visible to any consumer whose waiting store follows it.
	if r.waiting.Swap(0) == 1 {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
	return true
}

// Pop blocks until a segment is available or cancel closes.
func (r *Ring) Pop(cancel <-chan struct{}) (Segment, bool) {
	for {
		h := r.head.Load()
		if h != r.tail.Load() {
			s := r.buf[h&r.mask]
			r.buf[h&r.mask] = Segment{}
			r.head.Store(h + 1)
			return s, true
		}
		// Bounded spin covers the common case where the producer is one
		// syscall away. Sixty-four iterations is under a microsecond.
		for i := 0; i < 64; i++ {
			if h != r.tail.Load() {
				break
			}
			runtime.Gosched()
		}
		if h != r.tail.Load() {
			continue
		}
		r.waiting.Store(1)
		// Re-check after announcing. If the producer published before this
		// load, we see it here. If it published after, it sees waiting==1
		// and signals. No interleaving loses the wakeup.
		if h != r.tail.Load() {
			r.waiting.Store(0)
			continue
		}
		select {
		case <-r.wake:
		case <-cancel:
			return Segment{}, false
		}
	}
}

// Shard picks the writer for a decrypted inner IP packet by 5-tuple hash so
// one flow never spans two TUN writer threads. Reordering inside the tunnel
// is then impossible by construction.
type Sharder struct {
	seed  maphash.Seed
	rings []*Ring
}

func NewSharder(n, ringSize int) *Sharder {
	s := &Sharder{seed: maphash.MakeSeed(), rings: make([]*Ring, n)}
	for i := range s.rings {
		s.rings[i] = NewRing(ringSize)
	}
	return s
}

func (s *Sharder) Pick(inner []byte) *Ring {
	var h maphash.Hash
	h.SetSeed(s.seed)
	switch {
	case len(inner) >= 24 && inner[0]>>4 == 4:
		// IPv4: src, dst, protocol, then ports if present and not fragmented.
		h.Write(inner[12:20])
		h.WriteByte(inner[9])
		if inner[6]&0x1f == 0 && inner[7] == 0 {
			ihl := int(inner[0]&0x0f) * 4
			if len(inner) >= ihl+4 {
				h.Write(inner[ihl : ihl+4])
			}
		}
	case len(inner) >= 44 && inner[0]>>4 == 6:
		h.Write(inner[8:40])
		h.WriteByte(inner[6])
		h.Write(inner[40:44])
	default:
		return s.rings[0]
	}
	return s.rings[h.Sum64()%uint64(len(s.rings))]
}
```

Lost wakeup argument, compactly. Go's `sync/atomic` operations are sequentially consistent. Producer order: `tail.Store(t+1)` then `waiting.Swap(0)`. Consumer order: `waiting.Store(1)` then `tail.Load()`. In any total order of these four operations, either the consumer's `tail.Load()` follows the producer's `tail.Store` (consumer sees data, does not sleep) or the consumer's `waiting.Store(1)` precedes the producer's `Swap` (producer sees 1, sends the token). The buffered channel of one guarantees the token is never dropped; a stale token only causes one spurious loop.

### 7.4 Corrected Kotlin

```kotlin
package org.winsvpn.engine

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.PerformanceHintManager
import android.system.Os

class WinnVpnService : VpnService() {

    private var physical: Network? = null
    private var hintSession: PerformanceHintManager.Session? = null
    private lateinit var cm: ConnectivityManager

    private val physicalCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            physical = network
            setUnderlyingNetworks(arrayOf(network))
        }
        override fun onLost(network: Network) {
            if (physical == network) physical = null
        }
    }

    override fun onCreate() {
        super.onCreate()
        cm = getSystemService(ConnectivityManager::class.java)
        // Resolve the physical transport before establish() so activeNetwork
        // ambiguity never enters the picture.
        cm.registerNetworkCallback(
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build(),
            physicalCallback
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val pfd: ParcelFileDescriptor = Builder()
            .setSession("Winn v3")
            .setMtu(1373)
            .addAddress("10.10.0.14", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("10.10.0.1")
            .setBlocking(false)
            .setMetered(false)
            .establish() ?: return START_NOT_STICKY

        // Single owner: Go. O_NONBLOCK is handled in Go via unix.SetNonblock.
        val tunFd = pfd.detachFd()

        val udpFd = Engine.openUdpSocket()
        protect(udpFd)
        physical?.let { net ->
            // fromFd dups; the wrapper owns only the dup and we close it here.
            ParcelFileDescriptor.fromFd(udpFd).use { dup ->
                runCatching { net.bindSocket(dup.fileDescriptor) }
            }
        }

        Engine.start(
            tunFd, udpFd, "192.168.4.36:9111",
            EngineConfig(
                rcvBufBytes = 8 shl 20,   // clamped to rmem_max anyway; log getsockopt
                sndBufBytes = 8 shl 20,
                writers = 4,
                readers = 2,
                enableGso = true,
                enableGro = true
            )
        )

        // ADPF: tell the scheduler these threads have a deadline. This is the
        // lever that keeps them on prime cores at high clocks. A wake lock is not.
        val tids = Engine.datapathTids()
        val phm = getSystemService(PerformanceHintManager::class.java)
        hintSession = phm?.createHintSession(tids, 5_000_000L) // 5 ms per batch target
        return START_STICKY
    }

    override fun onRevoke() {
        teardown()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        cm.unregisterNetworkCallback(physicalCallback)
        super.onDestroy()
    }

    private fun teardown() {
        hintSession?.close()
        hintSession = null
        Engine.stop() // closes tun fd, then udp fd, then wakes parked readers via eventfd
    }
}
```

`Engine.datapathTids()` is the gomobile export that returns `unix.Gettid()` from each locked datapath goroutine. Go should call `reportActualWorkDuration` through a JNI callback per batch; if that plumbing is too much for this round, the session alone with a target duration still biases placement upward.

---

## 8. Stage 3 demands

Measurements, not estimates. Each one closes a dispute above.

1. Winn v3 header layout, byte exact. Resolves the 1.73 versus 1.81 Gbps ceiling.
2. `cat /proc/sys/net/core/rmem_max` on handset and `aicore`; `getsockopt(SO_RCVBUF)` readback in both engines at startup. Resolves the 16 MB question permanently.
3. `nstat -az UdpRcvbufErrors UdpInErrors` on `aicore` during a saturating handset upload. The engine's zero drop counter cannot see these.
4. `Segments / Aggregates` from 7.2 on the handset under saturating download. Below 1.5 means the Wi-Fi driver bypasses GRO and `recvmmsg` is the fallback.
5. `simpleperf record` on the handset datapath threads, 30 seconds at saturation. Settles the 1.2 us versus 3.5 us TUN write dispute between Podium 3 and me.
6. `grep UDP_MAX_SEGMENTS include/linux/udp.h` for the `aicore` kernel source, or the runtime probe from 7.1.
7. `cat /sys/class/net/winn3gw0/tx_queue_len` on `aicore` before and after the `txqueuelen` change, with `ip -s link` `dropped` counters under Double VPN load.
8. `nft list flowtable inet winn_relay ft` plus `conntrack -L | grep -c OFFLOAD` under load, confirming established flows hit the fast path.

Podium 2's arithmetic, Podium 3's framing and cipher analysis, and the shared conclusion that the syscall path is the ceiling all survive this audit. Podium 1's buffer change, GSO direction, MTU model, and forwarding ruleset do not.
