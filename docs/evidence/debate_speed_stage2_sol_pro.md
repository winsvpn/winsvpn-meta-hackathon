# Stage 2 Cross-Podium Rebuttal

## Executive finding

Crypto is not the limiting resource.

The active ceiling is a serialized packet pipeline with three demonstrated failure points: one virtio receive queue, `udp_rcvbuf_errors = 96,200`, and a session that tears down only after offered uplink exceeds 600 to 700 Mbps. UDP GSO and GRO may reduce kernel work substantially, but Podium 3 has not provided a correct receive implementation or empirical proof that the virtio device actually delivers the assumed coalescing ratio.

The session teardown must be fixed before throughput tuning. A faster path that still kills the session is not a solution.

---

# 1. Audit of Podium 1

## 1.1 Correct: primitive crypto has ample capacity

Podium 1 states:

> “ChaCha20-Poly1305 consumes less than a quarter of a single Haswell core.”

That conclusion follows from the supplied benchmark.

At 1 Gbps per direction:

\[
C_{\text{ChaCha}} = 125/1218 = 0.1026\text{ core}
\]

\[
C_{\text{AES-GCM}} = 125/1611 = 0.0776\text{ core}
\]

At 2 Gbps full duplex aggregate:

\[
C_{\text{ChaCha}} = 250/1218 = 0.205
\]

\[
C_{\text{AES-GCM}} = 250/1611 = 0.155
\]

At the raw handset capacity, 1.7427 Gbps down plus 1.6529 Gbps up:

\[
C_{\text{ChaCha}} = 3.3956/9.75 = 0.348\text{ core}
\]

\[
C_{\text{AES-GCM}} = 3.3956/12.89 = 0.263\text{ core}
\]

Even near 3.4 Gbps aggregate, measured primitive throughput consumes less than 0.35 core.

One qualification remains. OpenSSL proves the Haswell hardware is capable. It does not prove that Winn v3’s exact Go or native AEAD implementation reaches the same throughput. Benchmark the production AEAD path and inspect `perf`, but do not build cipher negotiation to solve the current collapse.

## 1.2 Unsupported: the alleged 600 to 650 Mbps interrupt ceiling

Podium 1 states:

> “A single 2.0 GHz Haswell core executing hardware interrupts, softirq packet handling, IP stack validation, and socket queuing saturates at approximately 600-650 Mbps.”

No cycle count, `perf` profile, softirq utilization, or dropped-packet correlation supports that number.

The supplied evidence proves serialization. It does not prove the exact saturation rate.

The settling measurements are:

```bash
mpstat -P ALL 1
perf record -F 999 -a -g -- sleep 30
nstat -az | grep -E 'UdpRcvbufErrors|UdpSndbufErrors|UdpInErrors'
cat /proc/softirqs
```

If CPU 4 reaches approximately 100 percent softirq while throughput stops increasing, the interrupt path is demonstrated. Until then, 600 to 650 Mbps is a Level 4 estimate.

## 1.3 Incorrect: RPS mask `3f` does not spread one tunnel across six CPUs

Podium 1 prescribes:

> `echo 3f > /sys/class/net/ens3/queues/rx-0/rps_cpus`

A single outer UDP tunnel normally presents one 4-tuple. RPS hashes that flow to one target CPU. It does not round-robin individual packets over all mask members.

Mask `3f` also includes CPU 4 and CPU 5, the two CPUs already handling virtio input and output interrupts. For a six-member mask, two of six possible targets overlap the IRQ CPUs:

\[
P(\text{IRQ overlap}) = 2/6 = 33.3\%
\]

Use `0f`, CPUs 0 through 3, while keeping IRQ 36 on CPU 4 and IRQ 37 on CPU 5. This gives multiple sessions four eligible RPS targets without steering upper-stack processing back onto either IRQ CPU.

## 1.4 Incorrect: XPS cannot distribute one transmit queue

Podium 1 states:

> “Map transmit processing across all cores: `echo 3f ... xps_cpus`”

There is only one transmit queue. XPS selects a transmit queue. With one available queue, every selection returns queue zero.

Setting an XPS mask cannot create queue parallelism absent from the virtio device. Leave XPS disabled and request multiqueue virtio from OVH as a separate host-side remediation.

## 1.5 Oversized socket defaults can increase queue latency

Podium 1 proposes 32 MiB global defaults and 64 MiB maxima.

That does not remove a blocked reader. It only increases the time before the same blocked reader reaches overflow. At 1 Gbps, 64 MiB of payload represents:

\[
T = 64 \times 2^{20}/125{,}000{,}000 = 0.537\text{ seconds}
\]

Accounting by skb truesize reduces payload capacity, but the queue remains hundreds of milliseconds deep. That is hostile to liveness detection.

Raise maxima so the application may request adequate buffers. Do not make every socket inherit 32 MiB. Fix the blocked receive path and set per-socket buffers explicitly.

## 1.6 The AWG packet-rate calculation is wrong

Podium 1 gives:

> “reducing packet processing rate from 102,400 pps to 86,805 pps”

For 1280 and 1440 byte packets:

\[
PPS_{1280}=10^9/(1280 \times 8)=97{,}656
\]

\[
PPS_{1440}=10^9/(1440 \times 8)=86{,}806
\]

The reduction is:

\[
1 - 86{,}806/97{,}656 = 11.11\%
\]

The conclusion remains correct. IPv4 outer AWG should use MTU 1440 and IPv4 inner TCP MSS 1400.

## 1.7 XRay buffer unit is wrong

Podium 1 prescribes:

> `bufferSize = 4194304`

Podium 3 cites the current XRay configuration code and its unit conversion: the configured value is multiplied by 1024. Therefore:

\[
4096 \times 1024 = 4{,}194{,}304\text{ bytes}
\]

Setting `4194304` would request:

\[
4{,}194{,}304 \times 1024 = 4{,}294{,}967{,}296\text{ bytes}
\]

That is 4 GiB per configured buffer, not 4 MiB.

The correct generated XRay value is `4096`, assuming the cited XRay unit semantics remain present in the built version.

## 1.8 `pm clear` is an unacceptable lockout remedy

Podium 1 recommends:

> “wipe application secure storage via `pm clear`”

That destroys more than the attempt state. According to the cited secure-store mapping, it also removes the enrolled profile and may invalidate or remove the client identity material.

Do not use `pm clear`. Delete only the settings record carrying `pin_attempt_state`, or wait through the bounded penalty without rebooting.

---

# 2. Audit of Podium 3

## 2.1 The CPU-ratio argument is not proof

Podium 3 states:

> “Clock ratio alone is roughly 4.5 GHz / 2.0 GHz = 2.25x, and Zen 4 over Haswell adds perhaps 1.5x IPC.”

“Perhaps 1.5x IPC” is explicitly heuristic. Multiplying an estimated boost clock by an estimated workload IPC ratio cannot establish the bottleneck.

The Ryzen and Haswell hosts also differ in virtualization, memory, NIC implementation, scheduler behavior, and host contention. The 2.59 throughput ratio is consistent with single-thread serialization. It does not prove it.

`perf`, per-CPU softirq utilization, and scheduler traces are the required evidence.

## 2.2 The cipher delta contains a factor-of-two error

Podium 3 states:

> “A gateway sealing and opening simultaneously at 2 Gbps aggregate spends 0.10 additional cores by choosing ChaCha20 over AES-GCM.”

The per-Gbps difference is:

\[
0.1026 - 0.0776 = 0.0250\text{ core/Gbps}
\]

At 2 Gbps aggregate:

\[
2 \times 0.0250 = 0.0500\text{ core}
\]

A 0.10 core difference occurs at 4 Gbps aggregate, such as 2 Gbps in each direction.

This does not alter the strategic conclusion. Cipher choice is not causing the collapse.

## 2.3 The UDP GRO patch is incomplete and would corrupt framing

Podium 3 proposes enabling `UDP_GRO` and then treats each `recvmmsg` result as one datagram.

That is not sufficient. UDP GRO may deliver several concatenated UDP payloads in one receive buffer, accompanied by ancillary metadata containing the logical segment size. The application must parse that control message and split the large receive buffer back into individual encrypted datagrams.

Podium 3’s shown receive changes do not perform that split.

If 16 datagrams of 1402 bytes are coalesced, the receive result can contain:

\[
16 \times 1402 = 22{,}432\text{ bytes}
\]

Passing those 22,432 bytes to a decoder expecting one Winn frame causes authentication or framing failure.

Required before enabling GRO:

1. Receive buffers large enough for coalesced payloads, normally up to 64 KiB.
2. Parse the `UDP_GRO` control message.
3. Split at the reported segment size.
4. Submit each segment independently to demux and AEAD processing.
5. Handle a shorter final segment.
6. Fall back to ordinary datagram handling when no GRO control message exists.

UDP GSO is promising. UDP GRO without this receive logic is broken.

## 2.4 The claimed 46x and 16x gains are theoretical upper bounds

Podium 3 states:

> “TX skbs 91,041/s to 1,979/s (46x); RX to 5,690/s (16x).”

The transmit arithmetic is:

\[
\left\lfloor 65507/1402 \right\rfloor = 46
\]

\[
91{,}041/46 = 1{,}979
\]

That is mathematically correct if all datagrams are consecutive, equal-sized, same-destination frames and the device accepts UDP segmentation.

The receive factor of 16 is assumed, not measured. The supplied telemetry does not include GRO coalescing size, virtio feature state, or post-GRO skb rate.

Verify first:

```bash
ethtool -k ens3 | grep -E \
  'generic-receive-offload|rx-udp-gro-forwarding|tx-udp-segmentation'

perf record -F 999 -a -g -- sleep 30
```

Then add application counters for physical receive calls, GRO superframes, recovered logical datagrams, and average segments per superframe.

## 2.5 “The single virtio queue is a red herring” is false today

The node currently has one receive ring and one transmit ring. Its receive interrupt work is entirely on CPU 4 and transmit interrupt work entirely on CPU 5.

Offloads may reduce the number of expensive pre-segmentation or post-coalescing operations. They do not make the present single queue irrelevant, and they do not create a second hardware or virtio ring.

The correct statement is narrower: a single ring may sustain multi-Gbps if batching and offloads reduce guest per-packet work enough. That proposition still requires measurement on this virtio device.

## 2.6 The liveness root cause is not yet proven

Podium 3 states:

> “That is the teardown above 700 Mbps.”

Its queue-delay arithmetic is useful:

\[
4096 \times 1402/125{,}000{,}000 = 45.9\text{ ms}
\]

With its estimated 3543-datagram socket capacity:

\[
3543 \times 1402/125{,}000{,}000 = 39.7\text{ ms}
\]

Combined:

\[
45.9 + 39.7 = 85.6\text{ ms}
\]

But the supplied telemetry does not identify the probe deadline, actual channel occupancy at teardown, GC pause duration, or teardown reason. An 85.6 ms queue cannot explain a five-second liveness timeout without additional stalls.

The mechanism is plausible. The causal declaration is premature.

Instrument these fields for every teardown:

* Last authenticated packet timestamp.
* Last authenticated control packet timestamp.
* Socket overflow counter.
* Demux queue high-water mark.
* Time blocked handing data to the next stage.
* Lock-wait duration.
* GC pause duration.
* Exact teardown reason and deadline.

## 2.7 Length-based control priority is remotely abusable

Podium 3 proposes:

> “if `msgs[i].N <= demuxControlPlaneMaxBytes`, lane = side.control”

That classification occurs before authentication. Any sender able to reach UDP 9111 can emit short datagrams. A strict-priority reader then spends its reserved capacity on attacker-generated short packets.

Control priority must be assigned after successful session lookup and authentication, or through a separately authenticated outer frame type. If control frames cannot be recognized safely before AEAD verification, reserve decrypt capacity rather than trusting packet length.

The stronger liveness rule is also simpler: any authenticated packet proves that the peer is alive. A session carrying authenticated bulk traffic must not die merely because a dedicated heartbeat waited behind that same traffic.

## 2.8 The CID copy-on-write patch preserves the unauthenticated write attack

Podium 3 identifies a serious pattern:

> “learnCIDsFromLongHeader populates it pre-authentication, from any source address.”

Its replacement still learns pre-authentication and rebuilds the full snapshot after each new CID. Once the table reaches 4096 entries, every attacker-generated new CID can force another approximately 4096-entry copy.

The patch removes a locked read scan but converts the attack into repeated allocation and copy work.

The security correction is to stop unauthenticated learning. Accept CID learning only after a validated QUIC handshake or source-validation event. If that cannot be done in the shared listener, separate Winn v3 and QUIC onto different sockets or ports.

## 2.9 Suricata CPU fanout criticism needs the RPS context

Podium 3 states:

> “every packet is classified in softirq on CPU 4 and fanout maps 100% of traffic to a single queue.”

That is true only if netfilter still processes those packets on CPU 4. After RPS redirects protocol processing to CPUs 0 through 3, CPU fanout would select only queues associated with those CPUs. It still would not use queues 4 and 5.

Either way, CPU fanout is the wrong choice here. Plain `--queue-balance` distributes flows over the configured queue range without coupling queue selection to the current CPU.

One TCP flow still remains on one NFQUEUE worker. Multiqueue helps when XRay or the speed test opens multiple flows.

## 2.10 The claim that encrypted TLS yields “zero detections” is too absolute

Suricata cannot inspect encrypted application plaintext after TLS establishment. It can still observe TLS handshake metadata, TCP behavior, record sizes, flow anomalies, and network-layer signatures.

The valid performance conclusion is narrower: full-copy inspection of every encrypted application record has sharply declining security value while retaining full packet-copy cost.

If TCP 443 is dedicated to XRay and policy permits bypass, accept it before NFQUEUE. That is the only resolution directly guaranteed to remove NFQUEUE drops from that path.

## 2.11 The Android and XRay stale-state findings are accepted

Podium 3 provides source-level evidence that:

* XRay `bufferSize` is already `4096`, meaning 4 MiB.
* The Android TUN reader already drains bursts.
* The TUN thread already uses elevated priority.
* Queue-full behavior is tail drop.

Those are superior to Podium 1’s stale prescriptions. Re-measure the current APK before modifying the handset pipeline.

---

# 3. Fortified technical position

## 3.1 CPU and cipher policy

Keep the existing production cipher unless the production implementation benchmark shows otherwise.

AES-256-GCM is 24.4 percent cheaper in core time than ChaCha20 on this Haswell:

\[
1 - 1218.911/1611.681 = 24.4\%
\]

That saving is useful but not enough to explain a session dying above 700 Mbps. Do not build runtime cipher agility as a throughput remedy.

Run the exact application benchmark:

```bash
go test ./... -run '^$' -bench 'AESGCM|ChaCha|Seal|Open' -benchmem
perf record -F 999 -p "$(pidof winn3-gateway)" -g -- sleep 30
```

## 3.2 Exact steering configuration

Keep the existing IRQ separation:

* CPU 4: virtio receive IRQ 36.
* CPU 5: virtio transmit IRQ 37.
* CPUs 0 through 3: RPS and gateway workers.

Apply:

```bash
IF=ens3

echo 0f > /sys/class/net/$IF/queues/rx-0/rps_cpus

sysctl -w net.core.rps_sock_flow_entries=32768
echo 32768 > /sys/class/net/$IF/queues/rx-0/rps_flow_cnt

# One TX queue. Disable misleading XPS configuration.
echo 00 > /sys/class/net/$IF/queues/tx-0/xps_cpus

sysctl -w net.core.rmem_max=33554432
sysctl -w net.core.wmem_max=33554432
sysctl -w net.core.netdev_max_backlog=250000
```

Why `0f`, not `3f`: it excludes both IRQ CPUs while retaining four flow targets.

Why 32,768 RFS entries: there is one receive queue, so its local table can consume the complete global table. Confirm migration and cache behavior with and without RFS. If Go worker migration causes unstable steering, disable RFS by setting both flow counts to zero while retaining RPS mask `0f`.

## 3.3 Gateway socket architecture

Use four `SO_REUSEPORT` sockets, one reader per socket, each executing batched `recvmmsg`.

This improves concurrent-client scale because different outer 4-tuples receive independent socket queues and readers. It does not parallelize one client’s single outer 4-tuple. Prove distribution with a packet counter per socket.

Set per-socket requested buffers to 16 MiB initially:

```text
SO_RCVBUF = 16 MiB
SO_SNDBUF = 16 MiB
```

Do not set 32 MiB global defaults. Verify effective allocation with:

```bash
ss -u -n -m -p | grep 9111
```

Acceptance is not “the buffer was enlarged.” Acceptance is zero increase in `UdpRcvbufErrors` during a sustained 1.5 Gbps offered-load test.

## 3.4 Two-stage pipeline and teardown correction

The socket pump must never block behind a full per-session data queue.

Required behavior:

1. Batch receive from the socket.
2. Perform bounded, lock-free or sharded session lookup.
3. Hand bulk packets to a bounded FIFO with nonblocking tail drop.
4. Continue draining the socket when a session queue is full.
5. Authenticate frames.
6. Route authenticated control frames to a reserved control lane.
7. Refresh liveness on every authenticated frame, including bulk data.
8. Tear down only after repeated authenticated-silence intervals, not merely a delayed heartbeat.

Tail drop is the operational choice because it retains FIFO order among admitted packets and avoids deliberate queue reordering. The peers’ categorical claim that drop-oldest necessarily causes an RTO is not mathematically established. TCP can fast-retransmit a missing head packet when later packets produce duplicate acknowledgments. Use tail drop anyway, but justify it through deterministic ordering and measured recovery, not the false claim that SACK cannot represent later data.

Instrument both policies before removal:

```text
queue drops
inner TCP retransmissions
duplicate ACKs
RTO count
cwnd minimum
session teardown count
```

## 3.5 UDP GSO and GRO

Implement UDP GSO after the nonblocking pipeline fix.

It can reduce transmit stack entries by up to:

\[
\left\lfloor 65507/1402 \right\rfloor = 46
\]

Do not assume that all batches reach 46. Record the measured mean and percentile segment counts.

Do not enable UDP GRO until the receiver:

* Allocates approximately 64 KiB receive buffers.
* Reads ancillary control data.
* Extracts the GRO segment size.
* Splits each coalesced buffer into logical datagrams.
* Processes every logical datagram independently.

Only then compare:

```text
syscalls per second
skbs per second
softirq CPU
gateway CPU
UdpRcvbufErrors
throughput
```

## 3.6 Suricata on TCP 443

Primary resolution: bypass NFQUEUE for dedicated XRay TCP 443.

Insert the ACCEPT rule before the NFQUEUE rule:

```bash
iptables -I WINVPN-INPUT 1 \
  -p tcp --dport 443 \
  -m conntrack --ctstate NEW,ESTABLISHED \
  -j ACCEPT
```

That deterministically removes TCP 443 from the path that has already dropped 125,188 packets.

If policy requires inline IPS, use multiqueue flow balancing:

```bash
-j NFQUEUE --queue-balance 0:5
```

Launch Suricata readers for queues 0 through 5. Do not add `--queue-cpu-fanout`. With RPS mask `0f`, CPU fanout would use at most four queue identities, while without RPS it can collapse onto the receive CPU.

Use `--queue-bypass` only under an explicit fail-open policy. It changes failure semantics when no userspace queue consumer is present. It is not a throughput flag that should be enabled silently.

Measure `/proc/net/netfilter/nfnetlink_queue` during load. Multiqueue is accepted only when both kernel drops and userspace drops remain zero.

## 3.7 AWG MTU and MSS

For a verified 1500-byte IPv4 outer path:

\[
20_{\text{IPv4}} + 8_{\text{UDP}} + 32_{\text{WG}} = 60
\]

\[
MTU_{\text{inner}} = 1500 - 60 = 1440
\]

For inner IPv4 TCP:

\[
MSS = 1440 - 20 - 20 = 1400
\]

Use MTU 1440 and MSS 1400. Reject 1408 absent observed additional data-packet overhead.

For an IPv6 outer path:

\[
1500 - 40 - 8 - 32 = 1420
\]

Use 1420 there, or let verified PMTUD and MSS clamping select the safe value.

## 3.8 XRay Android

The current generated value should be:

```json
"bufferSize": 4096
```

Under the cited XRay unit conversion, that is 4 MiB.

Prefer direct gateway IP transport only when an A/B test verifies:

* TLS certificate validation succeeds.
* SNI behavior remains correct.
* The direct route is reachable under the intended network restrictions.
* Throughput and latency beat the Cloudflare route.

Do not assume that direct IP with a CDN hostname as SNI is valid. Prove it with the actual certificate and origin configuration.

## 3.9 Android TUN pump

Do not rewrite the current pump before remeasurement. The cited tree already contains burst draining, one wake per burst, elevated priority, and tail-drop overflow.

Run a current-build test and collect:

```text
packets per wake
packets per TUN read burst
queue high-water mark
tail-drop count
futex wakes per second
TUN thread CPU
uplink throughput
```

`Thread.MAX_PRIORITY` is not itself proof of better throughput. The acceptance criterion is reduced wake frequency and higher measured uplink.

## 3.10 Decoy calculator lockout

First recovery path: stop rebooting, wait at least 300 seconds, then enter the UI sequence exactly once:

```text
1 4 2 5 3 6 =
```

For immediate debug-build recovery, preserve the enrolled profile and remove only the settings record:

```bash
adb -s REDACTED_SERIAL shell am force-stop org.winsvpn.app.debug

adb -s REDACTED_SERIAL shell run-as org.winsvpn.app.debug \
  ls -la files/secure_state

adb -s REDACTED_SERIAL shell run-as org.winsvpn.app.debug \
  rm -f files/secure_state/prefs.dat
```

Based on the cited mapping:

* `prefs.dat` contains `vpn_settings.txt`, including `pin_attempt_state`.
* `profile.dat` contains `user_pin.txt`.

Do not delete `profile.dat`. Do not use `pm clear`. Do not rewrite a hashed credential as plaintext.

If verification still fails after removing the attempt state, inspect for `PinReenrollmentRequired`. That indicates a legacy credential migration problem, not an active rate-limit penalty.

---

# Final priority order

1. Make the receive pump nonblocking and instrument the exact teardown reason.
2. Refresh liveness on any authenticated traffic and isolate authenticated control processing.
3. Apply RPS mask `0f`, keep IRQs on CPUs 4 and 5, leave XPS disabled.
4. Add `SO_REUSEPORT` readers and explicit per-socket buffers.
5. Implement UDP GSO, then implement GRO only with proper ancillary parsing and segmentation.
6. Bypass dedicated XRay TCP 443 before NFQUEUE. If forbidden, deploy flow-balanced NFQUEUE workers without CPU fanout.
7. Keep AWG at 1440 and MSS 1400 for verified IPv4 outer transport.
8. Retain XRay `bufferSize = 4096`; do not request 4 GiB accidentally.
9. Re-test the already-patched Android TUN pump.
10. Clear only `pin_attempt_state`; preserve the credential and device identity.

The binding defect is not AEAD arithmetic. It is queueing and serialization that first drops UDP packets, then starves authenticated progress, then destroys the entire session.