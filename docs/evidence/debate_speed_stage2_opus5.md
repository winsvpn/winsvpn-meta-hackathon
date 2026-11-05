I have what I need. Verification was done against the shipping tree; live web search was denied in this session, so every claim below rests on repo evidence (cited by `file:line`) or arithmetic, and I mark the two places where external confirmation is still outstanding.

---

# Podium 3: Claude Opus 5. Stage 2 Cross-Podium Rebuttal

## 0. Threshold finding: both podiums audited a system neither read

Before any individual claim, one structural objection governs this entire stage.

Podium 1 and Podium 2 each prescribed a remediation package. I checked that package against the shipping tree. The majority of it is **already deployed, and deployed at higher values than either podium recommended.**

| Control | Shipped value | Evidence | Podium 1 asked for | Podium 2 asked for |
|---|---|---|---|---|
| `net.core.rmem_max` | **134217728** | `server/wins_data_plane_setup_ONETOUCH.sh:4235` | 67108864 | 67108864 |
| `net.core.wmem_max` | **134217728** | `server/wins_data_plane_setup_ONETOUCH.sh:4236` | 67108864 | 67108864 |
| `net.core.rps_sock_flow_entries` | **65536** | `server/wins_data_plane_setup_ONETOUCH.sh:4241` | 32768 | 32768 |
| `rps_flow_cnt` | **16384** | `server/wins_data_plane_setup_ONETOUCH.sh:6800` | 4096 | 32768 |
| `netdev_max_backlog` | **250000** | `server/wins_data_plane_setup_ONETOUCH.sh:4237` | not raised | 65536 |
| `rps_cpus` / `xps_cpus` | all cores | `server/wins_data_plane_setup_ONETOUCH.sh:6805-6807` | `3f` | `3f` |
| `recvmmsg` receive batching | **batch 32** | `cmd/winn3-gateway/cover_demux.go:147,189` | "replace the single-threaded read loop" | "use `recvmmsg`, batch 64" |
| `sendmmsg` transmit batching | **batch 64** | `cmd/winn3-gateway/cover_demux.go:158-159` | not mentioned | "use `sendmmsg`" |
| `SO_RCVBUF` with granted readback | **8 MiB, hard-fails under 4 MiB** | `cmd/winn3-gateway/udp_socket_buffers.go:19,27,64-76` | set 64 MiB | set 32 MiB, log getsockopt |
| Android TUN `O_NONBLOCK` burst drain | **shipped** | `WinnV3AndroidTun.kt:79-80,112,358-388` | "set O_NONBLOCK, drain to EAGAIN" | "drain until EAGAIN" |
| Android single notify per burst | **shipped** | `WinnV3AndroidTun.kt:410-421,480-506` | "issue a single notifyAll" | implied |
| `THREAD_PRIORITY_URGENT_AUDIO` | **shipped** | `WinnV3AndroidTun.kt:289` | "elevate to URGENT_AUDIO" | downgrade to `DISPLAY` |
| XRay `bufferSize` | **4096 (= 4 MB)** | `VpnTunnelService.kt:2012` | set `4194304` | resize a kernel pipe |
| AWG inner MTU | **1440** | `lib/main.dart:286-287` | "current state 1280" | set 1440 |
| AWG MSS clamp | **1400 + pmtu backstop** | `wins_data_plane_setup_ONETOUCH.sh:7223-7232` | "current state 1240" | set 1400 |

Twelve of the fourteen headline recommendations across both podiums are already in the tree. Six of them are **downgrades** of the deployed value.

This matters for one reason and it is the reason that decides the debate: **the node still collapses at 600 to 700 Mbps with all of that already in place.** Therefore the bottleneck is not in any of it. Both podiums spent their Stage 1 budget on a config that is already live, and neither opened `cover_demux.go`.

I did. The answer is in there.

---

## 1. The actual serialization point: an O(n) locked scan on every fourth datagram

This is the finding neither peer reached, and it is dispositive.

`cmd/winn3-gateway/main.go:815` sets `conn: cover.v3` unconditionally. `startCover` is mandatory, not optional (`cover.go:63-66` returns an error when cover flags are absent). So **every v3 datagram on the Canada gateway traverses `splitUDP.pump()`**, which calls `routeQUIC()` per datagram at `cover_demux.go:220`.

Here is `routeQUIC`, verbatim, at `cmd/winn3-gateway/cover_demux.go:284-299`:

```go
func (s *splitUDP) routeQUIC(pkt []byte) bool {
	if isQUICLongHeader(pkt) {
		return true
	}
	if len(pkt) < 2 || pkt[0]&quicHeaderFormLong != 0 || pkt[0]&quicFixedBit == 0 {
		return false
	}
	s.cidMu.Lock()
	defer s.cidMu.Unlock()
	for cid := range s.cids {
		if len(pkt) >= 1+len(cid) && string(pkt[1:1+len(cid)]) == cid {
			return true
		}
	}
	return false
}
```

`maxLearnedCIDs = 4096` (`cover_demux.go:301`). The map is a Go map with randomized iteration order, so there is no early-exit locality.

**Level 3 derivation.** The file's own design note at `cover_demux.go:34-35` establishes that a v3 datagram is high entropy, and bases its false-positive analysis on exactly that. So byte 0 is uniform. The early-out at line 288 fails, and the locked scan runs, when `pkt[0]&0x80 == 0` **and** `pkt[0]&0x40 != 0`:

$$P(\text{locked scan}) = \tfrac{1}{2} \times \tfrac{1}{2} = 0.25$$

One in four v3 datagrams takes a process-global mutex and linearly scans up to 4096 learned connection IDs with a string comparison each.

Wire rate at the repo's own stated v3 message ceiling of 1402 bytes (`cover_demux.go:59`):

$$1402 + 8_{\text{UDP}} + 20_{\text{IPv4}} + 14_{\text{Eth}} + 4_{\text{FCS}} + 8_{\text{preamble}} + 12_{\text{IFG}} = 1468 \text{ B} = 11{,}744 \text{ bits}$$

$$\text{pps at 1 Gbps} = \frac{10^9}{11{,}744} = 85{,}150$$

Datagrams entering the locked scan per second:

$$0.25 \times 85{,}150 = 21{,}288$$

Worst-case comparisons per second with a full CID table:

$$21{,}288 \times 4096 = 87{,}195{,}648 \approx 8.7 \times 10^7$$

Cycle budget on a 2.0 GHz core, if the pump did nothing else at all:

$$\frac{2 \times 10^9}{8.72 \times 10^7} = 22.9 \text{ cycles per comparison}$$

A bounds check, a length compare, a `memcmp`, and a Go map iterator advance do not fit in 23 cycles. And the pump must also issue the `recvmmsg`, classify, allocate, and hand off. **At a populated CID table this single function cannot sustain 1 Gbps on this hardware.** That is the ceiling.

Two properties of this bug explain the telemetry better than any hypothesis either peer offered:

1. **It is load-history dependent.** `s.cids` grows only as QUIC cover traffic arrives (`cover_demux.go:303-328`). A cold gateway scans a small map and runs fast. A gateway that has served cover traffic scans a large one. That is why the collapse point is reported as a *range* ("above 700-900 Mbps"), not a constant. A hard architectural ceiling would be a constant.
2. **It sits upstream of everything both podiums blamed.** The pump goroutine stalling is precisely what fills the 8 MiB socket buffer, which is what produces `udp_rcvbuf_errors`, which is what starves the liveness probe, which is what tears the session down. The repo already documented that chain at `cover_demux.go:153-158`. Nobody found what stalls the pump. It is this.

**Remediation.** Make the classifier lock-free and O(1). QUIC short-header DCIDs on this listener are issued by the gateway's own stack, so they have a length the gateway controls. Index them by a fixed-width prefix in an immutable map swapped through an `atomic.Pointer`, so the read path takes no lock and does one hash lookup. The write path (CID learning) rebuilds and swaps, which is cheap because it runs per handshake, not per datagram.

---

## 2. Three more per-datagram costs in the same loop

The batch that `recvmmsg` assembles is **destroyed one datagram at a time immediately afterward.** Both podiums recommended adding batching. Batching exists. What neither checked is what happens to the batch after the syscall returns.

`cover_demux.go:189` reads up to 32 datagrams in one call. Then `cover_demux.go:224-232` pushes them into `side.incoming` **individually**. The consumer at `cover_demux.go:437` pulls them back out **individually**, inside a four-arm `select`. So the syscall rate falls 32x and nothing else does.

Per datagram, on the hot path, at 85,150 pps:

**(a) A dead heap allocation.** `cover_demux.go:217`:
```go
na: net.UDPAddrFromAddrPort(msgs[i].Addr),
```
`na` is read only by `demuxSide.ReadFrom` (`cover_demux.go:401,410`). The v3 read loop calls `ReadFromUDPAddrPort` (`main.go:1714`), which returns `pkt.addr` and never touches `pkt.na` (`cover_demux.go:364-374`). `net.UDPAddrFromAddrPort` allocates the `*net.UDPAddr` and, via `AsSlice()`, the IP backing array: two allocations, roughly 64 bytes, **entirely dead work on the hot path.**

$$85{,}150 \times 64 \text{ B} = 5.45 \text{ MB/s of pure garbage}$$

Against `GOMEMLIMIT=96MiB` (`cover_demux.go:52`) that is a GC cycle roughly every 7 to 18 seconds from this one line, depending on which trigger fires first. Every GC cycle drains `sync.Pool`, which is the exact self-sustaining allocation loop this file warns about at `cover_demux.go:50-56`. The file diagnosed the disease and then reintroduced it three lines into the fix.

**(b) A mutex per datagram to read a field that is always zero.** `cover_demux.go:420-424` takes `d.mu` on every `recv()` to read `readDeadline`. `main.go:1729` clears that deadline to the zero value after the readiness probe and never sets it again in steady state. So the gateway performs 85,150 lock/unlock pairs per second to read a zero. Replace with an `atomic.Int64`.

**(c) Two hchan lock acquisitions per datagram.** 170,300 per second on a single channel shared between the pump goroutine and the read loop goroutine, on two different Ps. This is the "demux lock contention" the deliberation topic asks about. It is not a `sync.Mutex` in the source. It is `runtime.hchan.lock`, and no amount of reading the code for `Lock()` calls would have found it.

**Remediation.** Carry `[]demuxDatagram` through the channel, not `demuxDatagram`. One channel operation per 32 datagrams instead of 32. Expose a `ReadBatch` on `demuxSide` and consume it in the read loop. Delete the `na` field. Make the deadline atomic.

---

## 3. Challenge: the single virtio queue is not the ceiling

> **Podium 1:** "The true throughput ceiling is architectural. It stems from hardware-level interrupt serialization combined with single-queue virtio limitations." / "A single 2.0 GHz Haswell core executing hardware interrupts, softirq packet handling, IP stack validation, and socket queuing saturates at approximately 600-650 Mbps."

The second sentence carries no citation, no benchmark, and no derivation. It is a Level 4 heuristic presented as mechanics, and it is falsified by the deliberation's own Level 1 telemetry.

**Empirical falsification.** Raw WAN, S26 Ultra to Canada gateway, no VPN: **1,742.7 Mbps down / 1,652.9 Mbps up.** That traffic crosses the same `ens3`, the same single virtio ring pair, the same IRQ 36 on CPU 4 and IRQ 37 on CPU 5. The node's own local Ookla reached **1,962 Mbps**. If interrupt serialization on a single queue capped this NIC at 600 to 650 Mbps, neither number could exist.

Podium 1's stated saturation point implies a per-packet cost of:

$$\frac{600 \times 10^6}{11{,}744} = 51{,}090 \text{ pps} \quad\Rightarrow\quad \frac{2 \times 10^9}{51{,}090} = 39{,}146 \text{ cycles per packet}$$

Thirty-nine thousand cycles for a virtio NAPI poll plus UDP receive. That is roughly an order of magnitude above any published softirq receive cost. The number is not defensible.

**Concession to Podium 2, in part.** Podium 2 wrote: *"The fixed virtio queue is a serialization point, but not an absolute 1 Gbps ceiling. The same VPS reached 1.96 Gbps in its local Ookla measurement."* Correct, and correctly reasoned. Podium 2 also correctly flagged that the UDP packet ceiling remains unproven because TCP and VPN UDP differ.

**I will name the difference Podium 2 left as `[UNVERIFIED]`.** It is GRO and GSO. TCP receive on that path coalesces many segments into one `sk_buff` before the socket layer sees them, so the expensive per-packet work is amortized. A plain UDP socket gets no such coalescing, so the VPN pays full per-datagram cost on every datagram while Ookla's TCP pays it once per aggregate. That asymmetry, not the queue count, is what separates 1,962 Mbps from 852 Mbps on identical hardware.

**Correcting Podium 1's pps arithmetic.** "At 1 Gbps with a 1373-byte inner MTU, ingress wire rate is 91,041 packets per second." Dividing line rate by the *inner* MTU omits the outer UDP header, IP header, Ethernet header, FCS, preamble, and inter-frame gap. Using the repo's own 1402-byte v3 message ceiling, the corrected wire rate is 85,150 pps, so the stated figure overstates by 6.9%. Small, but every downstream budget in that submission inherits it.

---

## 4. Challenge: RPS cannot help a single-flow speed test, and the mask is wrong

> **Podium 1, Required Kernel and Gateway Remediation, item 1:** "Distribute packet processing across all 6 vCPUs post-interrupt: `echo 3f > /sys/class/net/ens3/queues/rx-0/rps_cpus`"

Two objections.

**First, it is already set, at a wider value.** `wins_data_plane_setup_ONETOUCH.sh:6805-6807` writes a full-core bitmask to every `rps_cpus` and `xps_cpus` on every interface. The companion sysctls at lines 4235-4241 are set to 2x and 4x what Podium 1 requests. Running Podium 1's commands literally would **halve** `rmem_max` and `rps_sock_flow_entries` and **quarter** `rps_flow_cnt`.

**Second, and more important: RPS buckets on the flow hash.** A speed test from one handset to one gateway is one source IP, one source port, one destination IP, one destination port. One 4-tuple. One RPS bucket. One CPU. Spreading across six cores distributes nothing when there is one flow to distribute.

Podium 2 stated this correctly and then prescribed the configuration anyway:

> **Podium 2:** "**RPS does not turn one queue into six hardware queues.** ... A single UDP four-tuple generally remains one RPS flow and therefore one processing CPU."

Right diagnosis, wrong follow-through. If that sentence is true, and it is, then the entire steering section is irrelevant to the measured benchmark and should have been labeled as such rather than shipped as remediation.

**Mask correction, for whenever multi-flow load does arrive.** Both podiums specify `rps_cpus = 3f` while simultaneously pinning IRQ 36 to CPU 4 and IRQ 37 to CPU 5. Mask `3f` includes CPUs 4 and 5. That steers protocol processing back onto the two cores the design just reserved for interrupt handling. If the partition is real, the mask must exclude them: `0f` for CPUs 0 through 3, aligned with the worker pinning so RFS lands each flow on the core that will read it. Podium 2 derived the four-worker partition from that split and then contradicted it one section later.

---

## 5. Challenge: `SO_REUSEPORT` is a concurrency feature, not a throughput fix, and the lane ID is a fingerprint

> **Podium 2:** "Attach an `SK_REUSEPORT` eBPF selector that maps the clear lane identifier to the corresponding reuseport socket. Include that identifier in AEAD associated data, so changing it invalidates authentication."

The AEAD binding protects integrity. It does nothing about **observability**, and observability is this protocol's entire threat model.

`cover_demux.go:34-35` states the design contract plainly: a v3 datagram is high entropy, and the classifier's false-positive rate is derived from that. The gateway "stays silent to unauthenticated peers" (`cover_demux.go:75-76`). A **cleartext, stable, per-session lane identifier in the leading bytes of every datagram** is exactly the selector a censor needs. It converts a protocol designed to be indistinguishable from random into one with a fixed observable field and a countable cardinality.

It also collides mechanically with `routeQUIC`'s first-byte classifier at `cover_demux.go:288`, which tests bits 0x80 and 0x40 of byte 0 to separate v3 from QUIC cover.

And it does not solve the stated problem. Podium 2 concedes this: *"Without multiple four-tuples or a reuseport BPF selector, one high-rate tunnel session can hash to one worker."* Requiring the client to open multiple 4-tuples is a protocol change, a handshake change, a client change, and a new correlation surface, purchased to parallelize a workload that is currently bottlenecked on a 23-cycle-budget mutex scan in one function.

Fix the pump first. If a single session then still cannot fill the pipe, revisit.

---

## 6. Challenge: both podiums are wrong about drop semantics, in opposite directions

This one is decided entirely by reading the file.

> **Podium 1:** "Both `toEngine` and `toHost` carrying in-order TCP streams must utilize tail-drop (`dropOldest = false`)."

> **Podium 2:** "For ordinary data, use drop-oldest on a bounded byte ring."

The shipping code already implements the correct split, and documents the measurement behind it. `cmd/winn-datapath/winn3_frame_device.go:82-98`:

```
// toHost drops the OLDEST. A datapath that drops the newest delivers a stale
// burst when the slow side wakes up; dropping the oldest keeps the queue
// current, which is what inner TCP recovers from best.
//
// toEngine drops the NEWEST, which is plain tail drop. This queue carries the
// uplink, an in-order inner TCP stream on its way out. Removing its HEAD
// deletes the lowest unacknowledged sequence number, and the receiver can no
// longer describe the hole with a SACK block, so the sender has to wait out an
// RTO instead: cwnd collapses to one, slow-starts back up, hits the same full
// queue and collapses again. Measured on a Samsung Galaxy S26 Ultra against the
// Canada gateway, the uplink sat between 21.5 and 255 Mbps with exactly that
// variance, while the same handset with no VPN did 1652.9 Mbps up.
```

Call sites: `winn3_frame_device.go:163-164` passes `dropOldest = false` for `toEngine`. Line 252-253 passes `true` for `toHost`.

Podium 1 asked for a change on `toEngine` that is already made, and for a regression on `toHost`. Podium 2 asked for a regression on `toEngine`, which is the precise change whose removal produced the 21.5 to 255 Mbps uplink variance cited in the deliberation's own telemetry.

Podium 1 does get the RTO-versus-SACK mechanism right, and that reasoning is sound. It is simply aimed at code that already applies it.

---

## 7. Suricata: I concede the primary, and I kill Podium 1's alternative

**Concession, to both.** Accepting TCP 443 before the NFQUEUE rule is correct. XRay traffic is TLS 1.3, Suricata cannot inspect the payload, and the 125,188 drops on NFQUEUE 0 are pure loss with no detection benefit. Podium 2's `conntrack --ctstate NEW,ESTABLISHED` form with the explicit `ip6tables` twin and the `--line-numbers` ordering check is the better-specified version. I adopt it.

**Concession to Podium 2 on scope.** *"Port 9111 bypasses NFQUEUE, so Suricata cannot explain Winn v3's port 9111 collapse."* Correct, and it is the right instinct: separate the two failures instead of writing one narrative over both.

**Challenge to Podium 1's alternative.**

> **Podium 1:** "`iptables -R WINVPN-INPUT <num> -p tcp -m tcp --dport 443 ... -j NFQUEUE --queue-balance 0:5 --queue-cpu-fanout --queue-bypass`"

`--queue-bypass` fails **open**. When no userspace listener is attached, packets are accepted uninspected. The repo already rejects this, by name, in two independent verifiers:

- `server/wins_core_server_setup_ONETOUCH.sh:2238-2239`: `err "Core package security preimage refused a fail-open --queue-bypass rule."`
- `server/wins_core_server_setup_ONETOUCH.sh:2563-2564`: rollback requires "the required fail-closed NFQUEUE policy"
- `server/wins_core_server_setup_ONETOUCH.sh:481`: `SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-0}"`

Applying Podium 1's alternative would be rejected by the installer's own preimage check and would fail the deployment. Podium 2 flagged the fail-open semantics correctly on general grounds. The repo turns that judgment into an enforced invariant.

---

## 8. AWG MTU and MSS: Podium 1 audited a stale file

> **Podium 1:** "Current state: Inner MTU 1280, MSS clamp 1240."

Neither figure is the shipping configuration.

- Client inner MTU: **1440**, both direct and stealth. `lib/main.dart:286-287`:
  ```dart
  static const int _directAwgMtu = 1440;
  static const int _stealthTransportMtu = 1440;
  ```
- Server MSS clamp: **1400**, on both `awg0` and `amn0`, both directions, with a `--clamp-mss-to-pmtu` backstop. `server/wins_data_plane_setup_ONETOUCH.sh:7223-7232`.

The 1240 figure appears at `server/final_iptables_requested.txt:80`. That file is a request artifact, not live configuration. The 1280 appears at `lib/winn_protocol_web_control_plane_main.dart:113`, which is the control plane, not the AWG data path.

So Podium 1's entire section 5 optimizes a state that does not exist, toward values that are already deployed.

**Arithmetic check on Podium 1's derivation.** "reducing packet processing rate from 102,400 pps to 86,805 pps at 1 Gbps."

$$\frac{10^9}{1280 \times 8} = 97{,}656 \text{ pps, not } 102{,}400$$

$$\frac{10^9}{1440 \times 8} = 86{,}806 \text{ pps} \quad \checkmark$$

102,400 pps corresponds to a 1220.7-byte packet. The true reduction is 11.1%, not the 15.2% the stated pair implies.

**Concession to Podium 2.** *"MTU 1408 and MSS 1400 are inconsistent."* Correct:

$$1408 - 20_{\text{IPv4}} - 20_{\text{TCP}} = 1368 \neq 1400$$

That catch is right, and it lands against the deliberation topic's own "1440/1408" phrasing. It does not land against the tree, which ships the consistent 1440/1400 pair.

**Partial challenge to Podium 2.** *"If 1408 is needed after PMTU testing, use `--clamp-mss-to-pmtu` in both directions rather than retaining 1400."* Already present at `wins_data_plane_setup_ONETOUCH.sh:7232`, and the file already documents why it is inert: line 7229 notes that a fixed 1400 **shadows** the pmtu rule, because `xt_TCPMSS` never raises an MSS. Substituting one for the other is not a free swap. The fixed clamp has to be removed for the pmtu rule to have any effect.

**AmneziaWG overhead, which Podium 2 left `[UNVERIFIED]`.** AmneziaWG's obfuscation parameters operate on handshake packets and on separate junk packets. The type-4 data packet header is unchanged from WireGuard at 16 bytes plus a 16-byte Poly1305 tag, so 1500 − 20 − 8 − 32 = 1440 holds for an IPv4 outer path. I flag this as resting on foundational knowledge rather than a capture, since web search was unavailable here. Confirm with `tcpdump -ni ens3 udp port <awg>` and check the observed data-packet length before treating 1440 as final.

---

## 9. XRay: Podium 1's value would request 4 GiB per connection

> **Podium 1:** "Action: Set `policy.levels.0.bufferSize = 4194304` (4 MB) in the generated XRay configuration."

XRay's config parser multiplies `bufferSize` by 1024. The unit is kB, not bytes. The shipping code says so explicitly, at `android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt:1997-1999`:

```
// Mind the unit. infra/conf/policy.go multiplies the configured value
// by 1024, so bufferSize 4096 means 4 MB per connection, not 4 KiB.
```

And ships `4096` at line 2012.

$$4{,}194{,}304 \times 1024 = 4{,}294{,}967{,}296 \text{ bytes} = 4 \text{ GiB per connection}$$

Applied to a handset, that is an immediate out-of-memory kill, not an optimization. The correct value is already deployed, and the comment block at `VpnTunnelService.kt:1985-1996` documents the root cause Podium 1 correctly identified: XRay's `readDefaultBufferSize` returns 4 KiB on `arm64` as a low-end-device concession, and the shipped engine is built `GOARCH=arm64`. Right diagnosis. Wrong unit. Already fixed.

**Challenge to Podium 2's mechanism.** Podium 2 prescribed `fcntl(fd, F_SETPIPE_SZ, ...)` with `F_GETPIPE_SZ` verification. The verify-what-the-kernel-actually-granted discipline is exactly right and I adopt it as a general rule. But the mechanism is aimed at the wrong object. XRay's `bufferSize` is a Go userspace buffer inside the XRay core, not a kernel pipe. `F_SETPIPE_SZ` will not change it, and no amount of pipe resizing reaches `policy.levels.0.bufferSize`.

**Cloudflare removal.** Both podiums recommend direct origin IP with preserved SNI. I concur, with Podium 2's honest caveat that the benefit is unmeasured. Add one constraint neither stated: removing the CDN removes the shared-IP anonymity set. That is a censorship-resistance cost, not only a performance change, and it should be a per-node policy decision rather than a global default.

---

## 10. Android TUN pump: Podium 1 recommended shipped code, Podium 2 recommended a downgrade

> **Podium 1, item 7:** "Set `O_NONBLOCK` on the tun descriptor via `Os.fcntlInt`. Read packets in a tight loop until `EAGAIN` (-1). Enqueue all packets without notifying. Issue a single `state.notifyAll()` once the kernel buffer is drained. Elevate pump thread priority to `Thread.MAX_PRIORITY` and `THREAD_PRIORITY_URGENT_AUDIO`."

Every clause of that describes code that already ships in `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt`:

| Clause | Line |
|---|---|
| `Os.fcntlInt(fd, F_SETFL, flags or O_NONBLOCK)` | `79-80` |
| `OsConstants.EAGAIN -> return -1` | `112` |
| drain loop, `MAX_BURST_PACKETS = 256` | `249, 358-388` |
| enqueue without notify (`notify = false` per packet in a drain) | `480-506` |
| single `notifyAll()` ending the burst | `410-421` |
| `Process.setThreadPriority(THREAD_PRIORITY_URGENT_AUDIO)` | `289` |
| `priority = Thread.MAX_PRIORITY` | `320` |

The file's own comment at line 331 even names the defect being fixed: "burst, drained a batch of exactly one, and did one AF_UNIX write carrying" a single packet. This is not a remediation. It is a description of the current tree.

> **Podium 2:** "`Process.setThreadPriority(Process.THREAD_PRIORITY_DISPLAY)`" and "Do not use real-time scheduling without starvation tests."

Two problems. `THREAD_PRIORITY_DISPLAY` is −4. `THREAD_PRIORITY_URGENT_AUDIO` is −19. Substituting one for the other is a fifteen-nice-level **reduction** on the packet pump, prescribed as a fix. And the stated justification conflates two different things: `setThreadPriority(THREAD_PRIORITY_URGENT_AUDIO)` sets a nice value under the normal scheduler. It does not request `SCHED_FIFO` or `SCHED_RR`. The starvation caution applies to real-time scheduling classes, which this code does not use.

Podium 2's verification commands (`ps -T -o PRI,NI,CLS`, reading `/proc/<pid>/task/<tid>/sched`) are good and I adopt them. The conclusion they were attached to is wrong.

**What both missed.** Android scheduling is governed by cpuset membership before nice value. A process in the `background` cpuset is confined to little cores regardless of how negative its nice is. During a speed test the tester app holds `top-app` and the VPN app does not. Confirm the pump's cpuset before attributing anything further to thread priority:

```bash
PID=$(adb shell pidof org.winsvpn.app.debug | tr -d '\r')
adb shell cat /proc/$PID/cgroup
adb shell cat /dev/cpuset/foreground/cpus /dev/cpuset/background/cpus
```

If the service lands in `background`, no nice value will recover the uplink, and the foreground-service and cpuset placement is the fix. I mark this as requiring on-device confirmation on the S26 Ultra; I could not run live search to pin the current Samsung cpuset layout.

---

## 11. Decoy calculator lockout: both remedies are unnecessary, and one is destructive

The lockout is bounded. `lib/local_security.dart:445-447`:

```dart
static const int lockoutThreshold = 5;
static const int baseDelaySeconds = 5;
static const int maxDelaySeconds = 300;
```

**Maximum lockout is 300 seconds.** Five minutes. And under lockout, `classifyCredentialEntry` returns `recordsAttemptFailure: false` (`lib/camouflage_policy.dart:326-334`), so continued entry attempts **cannot extend it**. It expires by time and nothing else.

The resolution to the S26 Ultra lockout is therefore: **stop rebooting the handset, leave the calculator untouched for 300 seconds, enter `142536` once.** No file surgery, no debug build, no `run-as`, no data loss.

The reboot clause matters, because `rearmAfterMonotonicRollback` (`lib/local_security.dart:495-502`) imposes a fresh 300 seconds on **every** reboot that occurs while a monotonic lockout is active. The telemetry's "monotonic rollback re-arming" is that path firing. It is self-inflicted by the reboot cadence, and it stops the moment the reboots stop.

> **Podium 1:** "Clear `pin_attempt_state` from `vpn_settings.txt` or wipe application secure storage via `pm clear org.winsvpn.app.debug`, re-seeding `user_pin.txt` with PIN `142536=`."

**Reject.** `pm clear` calls `clearApplicationUserData()`. That is the same primitive the app uses for its **duress wipe** (`MainActivity.kt:254-256`: `"emergencyWipeAppData"` ... "erases ALL of this app's data with no user confirmation and then terminates the process"). Running it destroys the enrolled credential, the VPN configuration, the subscription state, and the Keystore entries bound to that UID, to clear a timer that expires on its own in five minutes.

Note also that `142536=` is not the credential. The `=` is the calculator's submit key; `lib/main.dart:11351` calls `_calculatorPinEntry.submit(...)` on it. Re-seeding `user_pin.txt` with the literal string `142536=` would enroll a credential that the keypad can never produce.

> **Podium 2, "Repair the rollback bug":** "On read, clear the lock deadline if any invariant fails."

**Reject.** `rearmAfterMonotonicRollback` is not a bug. It is control M-15, and `lib/local_security.dart:404-414` and `486-494` document why it deliberately re-arms rather than clears: a pre-reboot deadline compared against a new monotonic epoch "could otherwise mean anything from an accidental near-permanent lockout to an accidental early release," and clearing on rollback hands any local attacker an unlimited-attempt oracle for the price of one reboot per five tries. Podium 2's `bootCount` state machine is well-constructed and would be the right design in a system that did not already have one. Here it converts a documented security control into a bypass.

**One real defect, which neither podium found.** `lib/main.dart:11100-11103` carries a stale comment:

```
// used so a locally-advanced wall-clock date/time cannot shorten a PIN
// lockout. No platform currently implements this method channel handler,
```

It does. Android implements it at `MainActivity.kt:245-252` returning `SystemClock.elapsedRealtime()`, iOS at `ios/Runner/AppDelegate.swift:1352-1353`, macOS at `macos/Runner/MainFlutterWindow.swift:1058`. The comment describes a pre-implementation state and will mislead the next reader into believing the monotonic path is dead code when it is the path that produced this very lockout. Correct the comment. Change no behavior.

**Concession to Podium 2, on method.** Its instrumentation-test verification, which exercises the real verifier rather than printing or rewriting the stored credential, is the right shape for proving `142536` works, and it is strictly better than Podium 1's re-seed. I adopt it, minus the state clearing, which is unnecessary once the 300 seconds elapse.

---

## 12. Cryptography: concurrence on the conclusion, challenge on the transfer

Both podiums conclude the Haswell core is not cipher-bound. Correct, and the arithmetic on both sides checks out.

Podium 1's full-duplex framing is the right one for a gateway, which decrypts on ingress and encrypts on egress:

$$\frac{250}{1218.911} = 0.2051 \text{ core}, \qquad \frac{250}{1611.681} = 0.1551 \text{ core}$$

Podium 2's headline figures (0.1026 and 0.0776) are per-direction and understate gateway load by exactly 2x, though its 2 Gbps line recovers the same numbers. Label the duplex assumption; the two submissions do not actually disagree.

**Where both overreach.** `openssl speed -evp` measures OpenSSL's assembly. The gateway is Go. Go's `chacha20poly1305` AVX2 path and Go's `crypto/aes` GCM path are different code from OpenSSL's, and on Haswell (no VAES, no AVX-512) the gap is not a rounding error. Podium 2 flagged this correctly and I reinforce it: the 1.322x AES advantage is an OpenSSL ratio, not a Winn v3 ratio, until measured in-process.

**Challenge to Podium 2's recommendation.** *"Use AES-256-GCM as Winn v3's default on Canada. Retain cipher negotiation for other processors."*

The suite is pinned: `winn3-x25519-mlkem768-chacha20poly1305-sha256`. Swapping the AEAD changes the suite identifier, the handshake transcript, and every deployed client. It buys 0.05 of one core out of six, on a node whose measured bottleneck is a mutex. And "retain cipher negotiation" reintroduces negotiable cryptography, which is a downgrade surface and an observable per-node variation. A pinned suite is a feature of this design. Trading it for 5% of one core is a bad exchange.

---

## 13. Fortified position: ranked remediation

**Tier 1, the ceiling. Nothing else matters until these land.**

1. Replace the O(n) locked CID scan at `cover_demux.go:284-299` with a lock-free fixed-width prefix lookup behind an `atomic.Pointer` to an immutable map.
2. Carry batches through the demux. `chan []demuxDatagram`, not `chan demuxDatagram`. Add `ReadBatch` to `demuxSide` and consume it in `main.go:1714`.
3. Delete the dead `net.UDPAddrFromAddrPort` at `cover_demux.go:217`. Construct it lazily inside `ReadFrom` only.
4. Replace `demuxSide.mu` with an `atomic.Int64` deadline.

Expected effect: removes roughly 87 million comparisons per second, 170,300 channel lock acquisitions per second, 170,300 allocations per second, and 85,150 mutex pairs per second from the single hardest serialization point in the gateway.

**Tier 2, the multi-Gbps lever.**

5. UDP GSO and GRO. `setsockopt(UDP_GRO)` on the listener so the kernel coalesces received datagrams, and the `UDP_SEGMENT` control message on transmit so one `sendmsg` emits up to 64 segments. This is the mechanism that separates the node's 1,962 Mbps TCP result from its 852 Mbps UDP result, and it is entirely absent from the tree: no `UDP_SEGMENT`, no `UDP_GRO`, no `SO_REUSEPORT` appears anywhere in `winn_protocol_experimental`. Verify support on kernel 6.8 with virtio before committing; I could not confirm virtio GRO behavior on this kernel without live search.

**Tier 3, verify before changing.**

6. `fq` `flow_limit` is **256** packets on the WAN root qdisc (`wins_data_plane_setup_ONETOUCH.sh:6820`, `tc qdisc replace ... fq limit 20480 flow_limit 256`). The gateway-to-client downlink is a single UDP 4-tuple, so it is a single `fq` flow, and 256 packets is 3.2 ms of buffer at 80,000 pps. Read the counter before touching it:
   ```bash
   tc -s qdisc show dev ens3   # look at flows_plimit
   ```
   A nonzero and growing `flows_plimit` during a downlink run implicates the qdisc. A flat zero exonerates it. This is a hypothesis with a cheap test, not a prescription.

7. Accept TCP 443 before NFQUEUE, in Podium 2's `conntrack`-qualified form, with the `ip6tables` twin. Never with `--queue-bypass`.

8. Correct the stale comment at `lib/main.dart:11101`. Change no lockout behavior.

**Tier 4, do not do.**

- Do not lower `rmem_max`, `rps_sock_flow_entries`, `rps_flow_cnt`, or `netdev_max_backlog` to either podium's values.
- Do not set `bufferSize` to 4194304.
- Do not change `toEngine` to drop-oldest or `toHost` to tail-drop.
- Do not run `pm clear`.
- Do not add a cleartext lane identifier.
- Do not unpin the cipher suite.

**Acceptance gate.** I adopt Podium 2's gate substantially unchanged; it is the strongest single artifact either peer produced. Two additions: capture `go tool pprof` mutex and block profiles, not only `perf lock`, because the contention in this gateway is on `runtime.hchan.lock` and a Go `sync.Mutex`, neither of which a C-oriented lock profile attributes legibly. And record `len(s.cids)` alongside each throughput sample, because if my diagnosis is right the collapse threshold will track it.

---

## 14. Concessions register

Conceded on evidence, not on courtesy:

1. **To Podium 2:** the virtio single queue is not an absolute ceiling, and the node's own 1.96 Gbps result proves it. Podium 2 reached this in Stage 1 and Podium 1 did not.
2. **To Podium 2:** accept TCP 443 before NFQUEUE, in its `conntrack`-qualified form with the IPv6 twin, is the correct primary. `--queue-bypass` fails open.
3. **To Podium 2:** Suricata on TCP 443 cannot explain a UDP 9111 collapse. Separating the two failures was the right analytical move.
4. **To Podium 2:** MTU 1408 with MSS 1400 is arithmetically inconsistent. The catch is valid.
5. **To Podium 2:** never trust a `setsockopt` or `fcntl` return; read back what the kernel granted. The tree already does this for `SO_RCVBUF` and it is the right general rule.
6. **To Podium 2:** verify PIN acceptance through an instrumentation test against the real verifier rather than by rewriting or printing the credential.
7. **To Podium 1:** the full-duplex framing of the cipher budget is the correct one for a gateway, and its arithmetic is right.
8. **To Podium 1:** the RTO-versus-SACK mechanism behind the drop-policy split is correctly reasoned, even though it is aimed at code that already applies it.
9. **To both:** cipher execution is not the bottleneck. That conclusion holds and I do not contest it.

Not conceded: the single-queue ceiling thesis, the RPS remediation package, the drop-semantics inversions, the `bufferSize` unit, the `pm clear` remedy, the M-15 rollback rewrite, the cleartext lane identifier, and the cipher-suite change.

**Standing position.** The Canada gateway is not interrupt-bound, not cipher-bound, and not buffer-bound. It is bound by a linear scan over as many as 4096 connection IDs, under a process-global mutex, on one in four datagrams, in a function that both peers' remediation packages leave untouched.
