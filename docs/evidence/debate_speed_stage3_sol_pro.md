# 1. Absorbed Points

## 1.1 The shipping tree already contains many proposed optimizations

Podium 3’s repository audit changes the baseline.

Level 1 source evidence shows:

* `rmem_max` and `wmem_max` are already 128 MiB.
* `rps_sock_flow_entries` is already 65,536.
* `rps_flow_cnt` is already 16,384.
* `netdev_max_backlog` is already 250,000.
* Gateway receive and transmit batching already use `recvmmsg` batch 32 and `sendmmsg` batch 64.
* The gateway requests an 8 MiB receive buffer and rejects an effective allocation below 4 MiB.
* Android already performs nonblocking burst drain, up to 256 packets, with one notification per burst.
* Android already applies `Thread.MAX_PRIORITY` and `THREAD_PRIORITY_URGENT_AUDIO`.
* XRay already emits `bufferSize: 4096`, meaning 4 MiB under XRay’s KiB conversion.
* AWG already uses MTU 1440 and MSS 1400.

These are source-tree facts, not proof that the Canada process is running that revision. The first deployment action is therefore binary and configuration attestation, not reapplying stale recommendations.

## 1.2 The cover demultiplexer contains a stronger serialization candidate

I absorb Podium 3’s `routeQUIC` finding.

The source performs a process-global locked CID scan for a random Winn v3 datagram whenever the first byte has bit `0x80` clear and bit `0x40` set. For uniformly distributed encrypted bytes:

\[
P(\text{scan})=\frac12 \times \frac12=\frac14
\]

Using Podium 3’s 1 Gbps wire-rate calculation:

\[
PPS=\frac{10^9}{11{,}744}=85{,}150
\]

At 4,096 CIDs, the worst unmatched path performs:

\[
85{,}150 \times 0.25 \times 4096
=87{,}193{,}600
\]

CID comparisons per second.

A 2.0 GHz core then has only:

\[
\frac{2\times10^9}{87{,}193{,}600}=22.9
\]

cycles per candidate comparison, before syscall return processing, allocation, channel operations, and delivery to Winn v3. That conditional budget is severe.

I also accept the accompanying source findings:

* A batch of 32 received datagrams is converted into individual channel sends.
* The consumer performs individual channel receives.
* `net.UDPAddrFromAddrPort` is constructed on the Winn v3 path even though `ReadFromUDPAddrPort` does not consume it.
* A mutex protects a steady-state deadline value that is normally zero.

The exact allocation count still requires `go test -benchmem` or compiler escape analysis. The unnecessary construction itself is established by the source.

## 1.3 RPS must exclude the interrupt CPUs

Podiums 1 and 3 correctly displaced mask `3f`.

CPU 4 handles IRQ 36. CPU 5 handles IRQ 37. Mask `3f` includes both CPUs, so two of six eligible RPS targets overlap the dedicated interrupt CPUs:

\[
P(\text{overlap})=\frac26=33.3\%
\]

The locked mask is `0f`, CPUs 0 through 3.

I also absorb the XPS correction. With exactly one transmit queue, every packet still selects `tx-0`; XPS cannot manufacture queue parallelism.

## 1.4 UDP GSO and GRO are the correct offload targets

`sendmmsg` reduces syscall count. It does not reduce the number of UDP skbs traversing the stack.

For 1,402-byte Winn datagrams, one legal UDP superframe can contain at most:

\[
\left\lfloor\frac{65{,}507}{1{,}402}\right\rfloor=46
\]

logical segments. UDP GSO can therefore reduce transmit skb submissions by as much as 46 times when a batch contains compatible datagrams.

Podium 3 was also right that UDP GRO cannot be enabled by merely enlarging the receive buffer. The receiver must parse the `UDP_GRO` ancillary control message and split the coalesced payload at the reported segment size. Otherwise several authenticated Winn frames are presented as one invalid frame.

## 1.5 Uplink queues require tail drop

I formally withdraw my Stage 1 recommendation to use drop-oldest for ordinary in-order uplink traffic.

The Level 1 handset A/B result controls:

* Drop-oldest produced 21.5 to 255 Mbps uplink.
* Tail drop stabilized uplink above approximately 600 to 800 Mbps.

The shipping split should remain:

* `toEngine`, uplink: tail drop.
* `toHost`, downlink: drop-oldest, pending a separate controlled A/B test.

Podium 1’s universal TCP explanation remains overstated. A missing queue head can still induce duplicate ACKs when later segments arrive, even though SACK cannot describe the missing bytes themselves. The measured uplink result, not that universal claim, locks tail drop for `toEngine`.

## 1.6 Several client-side remediations are already present

The following changes are rejected because the shipping source already contains them:

* Do not change XRay `bufferSize` from `4096` to `4194304`. The latter becomes 4 GiB after multiplication by 1,024.
* Do not replace the Android TUN pump before profiling the installed APK.
* Do not lower `THREAD_PRIORITY_URGENT_AUDIO` to `THREAD_PRIORITY_DISPLAY`.
* Do not change AWG from 1440 and 1400 to values it already uses.

The remaining Android question is runtime placement. Nice priority does not override cpuset restrictions, so the S26 Ultra process and pump thread must be inspected during the speed test.

## 1.7 Suricata and PIN recovery are settled

The 125,188 NFQUEUE drops establish that TCP 443 is losing packets in the inline path. Winn v3 port 9111 bypasses that queue, so the Suricata defect is specific to XRay and other TCP 443 traffic.

The calculator lockout is bounded by source constants at 300 seconds. During lockout, attempts are recorded with `recordsAttemptFailure: false`, so entries do not extend the timer. Rebooting can rearm the monotonic rollback protection.

The correct recovery is simple: stop rebooting, wait 300 seconds after the last rearm, then enter `142536` and press `=` once. `pm clear` is rejected because it destroys application identity and configuration.

# 2. Defended Grounds

## 2.1 Cryptography is not the primary bottleneck

The supplied OpenSSL measurements establish the Haswell instruction capacity:

\[
C_{\text{ChaCha,1Gbps}}=\frac{125}{1218.911}=0.1026\text{ core}
\]

\[
C_{\text{AES,1Gbps}}=\frac{125}{1611.681}=0.0776\text{ core}
\]

At the handset’s measured aggregate raw rate:

\[
1.7427+1.6529=3.3956\text{ Gbps}
\]

\[
C_{\text{ChaCha}}=\frac{3.3956}{9.75}=0.348\text{ core}
\]

\[
C_{\text{AES}}=\frac{3.3956}{12.89}=0.263\text{ core}
\]

AES-GCM uses 24.4 percent less core time in this OpenSSL benchmark:

\[
1-\frac{1218.911}{1611.681}=0.244
\]

That saving cannot explain a session teardown accompanied by 96,200 receive-buffer errors. Keep the pinned production suite. Do not add cipher negotiation as a throughput remedy.

One verification remains mandatory: benchmark Winn v3’s exact production AEAD implementation because OpenSSL assembly is not Go’s implementation.

```bash
go test ./... -run '^$' \
  -bench 'AESGCM|ChaCha|Seal|Open' -benchmem

perf record -F 999 -p "$(pidof winn3-gateway)" -g -- sleep 30
```

## 2.2 Lock the interrupt and steering configuration

Use this partition:

* CPU 4: virtio receive interrupt and NAPI.
* CPU 5: virtio transmit completion.
* CPUs 0 through 3: RPS, protocol processing, and gateway workers.

```bash
IF=ens3

printf '10\n' > /proc/irq/36/smp_affinity
printf '20\n' > /proc/irq/37/smp_affinity

printf '0f\n' > /sys/class/net/$IF/queues/rx-0/rps_cpus

sysctl -w net.core.rps_sock_flow_entries=65536
printf '16384\n' > \
  /sys/class/net/$IF/queues/rx-0/rps_flow_cnt

# One transmit queue. XPS cannot distribute it.
printf '00\n' > \
  /sys/class/net/$IF/queues/tx-0/xps_cpus

sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.core.netdev_max_backlog=250000
```

Prevent `irqbalance` from moving IRQs 36 and 37.

RPS does not parallelize one outer UDP four-tuple. It gives separate flows eligible protocol-processing CPUs and prevents those flows from returning to CPUs 4 or 5. The single-flow remedy must occur inside the gateway loop through constant-time classification, batching, and offload.

The single virtio queue is a serialization point. It is not a hard sub-gigabit ceiling. The same node reached 1.962 Gbps over its TCP path, which falsifies any unconditional claim that the queue itself caps the VPS at 600 to 650 Mbps.

## 2.3 Replace the serialized gateway path

The locked architecture is:

1. Four `SO_REUSEPORT` sockets, with one pinned reader on each CPU from 0 through 3.
2. Kernel reuseport hashing by ordinary outer four-tuple.
3. No cleartext lane identifier.
4. One `recvmmsg` batch retained as a batch through classification and handoff.
5. An O(1), lock-free QUIC CID read path.
6. Nonblocking delivery into bounded per-session queues.
7. Batched encryption and decryption.
8. UDP GSO on transmit.
9. UDP GRO only after correct ancillary parsing.

`SO_REUSEPORT` distributes concurrent sessions. It does not split one high-rate outer flow. Its value is isolation: one blocked session cannot monopolize the sole socket queue and reader.

CID registration must occur only after QUIC validation. Long-header QUIC packets can reach the QUIC stack first; once the handshake validates, the stack can publish its server-issued fixed-width CID into an immutable lookup map. The packet read path then performs one lookup through an atomic map pointer and takes no process-global mutex.

Do not retain unauthenticated CID learning. A 4,096-entry cap limits storage, but it does not prevent an attacker from forcing repeated insertion and copy work.

## 2.4 Size buffers as transient shock absorbers

Keep 128 MiB global maxima. Request 16 MiB per gateway socket for both receive and transmit, then read the granted values back with `getsockopt`.

At the measured 1.6529 Gbps uplink, 16 MiB contains at most:

\[
T=\frac{16\times2^{20}\times8}{1.6529\times10^9}
=81.2\text{ ms}
\]

of ideal payload. Actual capacity is lower because UDP skb accounting exceeds payload size.

That buffer can absorb a bounded scheduling stall. It cannot repair a reader blocked on a mutex or full channel. The acceptance condition is zero increase in `UdpRcvbufErrors`, not merely a successful `setsockopt`.

```bash
nstat -az | grep -E \
  'UdpRcvbufErrors|UdpSndbufErrors|UdpInErrors'

ss -u -n -m -p | grep 9111
```

## 2.5 Prevent overload from becoming session death

The socket pump must never block behind a full per-session data queue.

Use these semantics:

* `toEngine`, uplink: bounded FIFO, nonblocking tail drop.
* `toHost`, downlink: retain shipping drop-oldest pending direct A/B evidence.
* Authentication occurs before control-plane priority.
* Authenticated control frames enter a reserved control queue.
* Any authenticated frame refreshes `lastAuthenticatedRx`.
* A delayed heartbeat cannot terminate a session while authenticated bulk traffic is arriving.
* Teardown requires authenticated silence for the configured retry interval, with the exact reason logged.

This follows a protocol proof. If a frame authenticates at time \(t\), the peer possessed the session key and the path delivered traffic at \(t\). A separate heartbeat received before \(t\) contains strictly older liveness information.

Record for every teardown:

```text
CID table size
last authenticated packet time
last authenticated control time
socket overflow counter
demux queue high-water mark
per-session drop count
channel block duration
CID lock wait duration
GC pause duration
exact timeout and teardown reason
```

## 2.6 Bypass NFQUEUE for dedicated XRay TCP 443

If TCP 443 is dedicated to XRay, accept it before NFQUEUE:

```bash
iptables -I WINVPN-INPUT 1 \
  -p tcp --dport 443 \
  -m conntrack --ctstate NEW,ESTABLISHED \
  -j ACCEPT

ip6tables -I WINVPN-INPUT 1 \
  -p tcp --dport 443 \
  -m conntrack --ctstate NEW,ESTABLISHED \
  -j ACCEPT
```

This deterministically removes the path that has already dropped 125,188 packets.

If policy requires inline inspection, use:

```bash
-j NFQUEUE --queue-balance 0:5
```

Run six Suricata queue readers. Do not add `--queue-cpu-fanout`, since queue choice would be tied to the current protocol-processing CPU. Do not add `--queue-bypass`, since that changes failure policy from fail-closed to fail-open.

A single TCP flow still maps to one NFQUEUE worker. Multiqueue helps only when XRay or the benchmark opens multiple flows.

## 2.7 Keep AWG at mathematically consistent MTU and MSS values

For a 1,500-byte IPv4 outer path:

\[
1500-20_{\text{IPv4}}-8_{\text{UDP}}-32_{\text{WG}}
=1440
\]

For inner IPv4 TCP:

\[
1440-20_{\text{IPv4}}-20_{\text{TCP}}
=1400
\]

Therefore retain:

```text
AWG inner MTU: 1440
IPv4 TCP MSS: 1400
```

Confirm actual AmneziaWG data-packet size with `tcpdump`. If the outer path is IPv6:

\[
1500-40-8-32=1420
\]

The corresponding inner IPv4 TCP MSS is 1380.

MTU 1408 and MSS 1400 cannot coexist mathematically. A 1408 tunnel MTU permits at most:

\[
1408-20-20=1368
\]

for inner IPv4 TCP MSS.

## 2.8 Retain the current XRay and Android values

XRay must remain:

```json
"bufferSize": 4096
```

Under the cited parser conversion:

\[
4096\times1024=4{,}194{,}304\text{ bytes}
\]

Use direct-origin IP transport when certificate validation, SNI, and reachability all pass. Do not enable `allowInsecure`. Compare direct and Cloudflare paths with the same endpoint, concurrency, and test duration.

For Android, test the installed APK before altering source. Collect:

```bash
PID=$(adb shell pidof org.winsvpn.app.debug | tr -d '\r')

adb shell cat /proc/$PID/cgroup
adb shell ps -T -p $PID -o PID,TID,PRI,NI,CLS,NAME
adb shell cat /dev/cpuset/foreground/cpus
adb shell cat /dev/cpuset/background/cpus
```

Also record packets per wake, packets per burst, queue high-water marks, tail drops, TUN thread CPU, and futex wakes per second. The source already has the requested burst drain and priority behavior.

## 2.9 Final acceptance gate

Each protocol must exceed 1 Gbps under sustained testing. No short speed-test spike qualifies.

For Winn v3:

* Greater than 1 Gbps in each tested direction.
* No teardown during at least ten minutes at offered load.
* Zero increase in `UdpRcvbufErrors`.
* CID table size, mutex profile, block profile, and GRO segment counters captured.

For AWG:

* Greater than 1 Gbps.
* Zero fragmentation growth on the verified 1,500-byte path.
* MTU 1440 and MSS 1400 confirmed in the live configuration.

For XRay:

* Greater than 1 Gbps.
* Zero NFQUEUE drops on the bypassed TCP 443 path.
* Direct-origin and Cloudflare results recorded separately.

For Android:

* No growth in uplink queue drops during the accepted run.
* Burst size materially greater than one packet.
* Pump thread placement confirmed outside a throughput-restricting background cpuset.

# 3. Irreconcilable Delta

Podium 3 declares the O(n) CID scan the proven current root cause. I hold that it is the strongest source-level suspect, but current causality still requires `len(s.cids)`, Go mutex and block profiles, and teardown correlation under the failing load.

Podium 1 treats the single virtio queue as a hard throughput ceiling and demands tail drop for both frame queues. The 1.962 Gbps TCP result disproves the hard ceiling, while the available handset evidence locks tail drop only for `toEngine`, not `toHost`.

The size of the UDP GSO and GRO gain remains unresolved until the Canada virtio path reports actual GSO segment counts, GRO coalescing ratios, skb rates, and post-change throughput.