# Podium 2 determination

**Canada CPU cryptography is not the primary bottleneck.**

At the measured 1024 byte EVP size:

\[
1\text{ Gbps}=125\text{ MB/s}
\]

\[
CPU_{ChaCha}=\frac{125}{1218.911}=0.1026\text{ core}
\]

\[
CPU_{AES}=\frac{125}{1611.681}=0.0776\text{ core}
\]

At 2 Gbps:

\[
CPU_{ChaCha}=0.2051\text{ core},\quad CPU_{AES}=0.1551\text{ core}
\]

AES-256-GCM produced 1.322 times the measured throughput of ChaCha20-Poly1305 on this Haswell VPS. [L1, L3]

Use AES-256-GCM as Winn v3's default on Canada. Retain cipher negotiation for other processors, but do not treat a ChaCha switch as the Canada performance fix. Android cipher performance remains [UNVERIFIED] until the same in-process benchmark is run on the S26 Ultra. The OpenSSL result also does not prove that Winn invokes the same assembly path, so confirm with `perf` rather than assuming.

The fixed virtio queue is a serialization point, but not an absolute 1 Gbps ceiling. The same VPS reached 1.96 Gbps in its local Ookla measurement. [L1] VPN UDP framing, userspace wakeups and packet sizes differ from that TCP workload, so its UDP packet ceiling remains [UNVERIFIED].

## 1. Canada interrupt and packet steering

Keep the existing hard IRQ separation:

```bash
# CPU 4 is bit 0x10. CPU 5 is bit 0x20.
printf '10\n' > /proc/irq/36/smp_affinity
printf '20\n' > /proc/irq/37/smp_affinity
```

Prevent `irqbalance` from undoing this assignment. Disabling it globally is an operational policy choice [UNVERIFIED]:

```bash
systemctl disable --now irqbalance
```

Apply RPS and XPS:

```bash
IF=ens3

sysctl -w net.core.rps_sock_flow_entries=32768

for q in /sys/class/net/$IF/queues/rx-*; do
    printf '3f\n' > "$q/rps_cpus"
    printf '32768\n' > "$q/rps_flow_cnt"
done

for q in /sys/class/net/$IF/queues/tx-*; do
    printf '3f\n' > "$q/xps_cpus"
done
```

`3f` is the six bit mask for CPUs 0 through 5:

\[
0x3f=2^6-1
\]

The flow table value 32768 is a concrete power-of-two tuning seed [UNVERIFIED]. Validate it against concurrent flow count and memory pressure.

**RPS does not turn one queue into six hardware queues.**

It moves receive protocol processing to other CPUs after the single virtio receive queue has delivered the packets. A single UDP four-tuple generally remains one RPS flow and therefore one processing CPU. XPS also cannot create a second transmit ring when only one ring exists.

Add a backlog allowance:

```bash
sysctl -w net.core.netdev_max_backlog=65536
```

The value 65536 is [UNVERIFIED]. Keep it only if `/proc/net/softnet_stat` shows backlog drops or `time_squeeze`; otherwise it merely permits more queued latency.

Persist these settings through a systemd oneshot service after `network-online.target`.

## 2. Reject the single locked demultiplexer

**Use a `SO_REUSEPORT` worker pool with protocol lanes. Plain `SO_REUSEPORT` is insufficient.**

Four workers are the initial topology:

\[
6\text{ vCPUs}-2\text{ IRQ-reserved CPUs}=4\text{ application CPUs}
\]

The optimality of four workers is [UNVERIFIED], but the count follows the selected CPU partition. Pin gateway workers to CPUs 0 through 3. Keep IRQ 36 on CPU 4 and IRQ 37 on CPU 5.

Each client session must create multiple UDP four-tuples. Each lane needs:

* An independent receive sequence and replay window.
* An authenticated lane identifier.
* A worker-owned session shard.
* No global demux mutex.
* Consistent inner-flow hashing so packets from one inner TCP flow remain ordered.

Attach an `SK_REUSEPORT` eBPF selector that maps the clear lane identifier to the corresponding reuseport socket. Include that identifier in AEAD associated data, so changing it invalidates authentication. Payload access and verifier behavior for the installed kernel build are [UNVERIFIED] and must be tested before rollout.

Without multiple four-tuples or a reuseport BPF selector, one high-rate tunnel session can hash to one worker. Merely opening four identical listeners does not solve the single-session problem.

TCP transport on port 9111 has the same limitation. One TCP connection has an ordered byte stream. Use multiple authenticated substreams if TCP fallback must exceed the capacity of one connection loop.

### Socket sizing

Start with a requested 32 MiB receive and send buffer per lane [UNVERIFIED]:

```bash
sysctl -w net.core.rmem_max=67108864
sysctl -w net.core.wmem_max=67108864
```

Application setup, before `bind`:

```go
const requestedSocketBuffer = 32 << 20 // 32 MiB, tuning seed [UNVERIFIED]

if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
    return err
}
if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, requestedSocketBuffer); err != nil {
    return err
}
if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, requestedSocketBuffer); err != nil {
    return err
}
```

Four requested receive buffers total 128 MiB:

\[
4 \times 32\text{ MiB}=128\text{ MiB}
\]

At 2 Gbps, that aggregate payload capacity corresponds to:

\[
\frac{128\times 2^{20}\times8}{2\times10^9}=0.537\text{ s}
\]

Linux socket accounting, `sk_buff` overhead and the doubled value reported by `getsockopt` make actual memory consumption different from this payload calculation [UNVERIFIED]. Check VPS `MemAvailable`, `sockstat` and cgroup memory before retaining the setting.

Log the effective `SO_RCVBUF` and `SO_SNDBUF` returned by `getsockopt`. Do not silently continue with a much smaller value.

### Batch the protocol loop

At a 1024 byte datagram payload:

\[
\frac{10^9}{1024\times8}=122070\text{ datagrams/s at 1 Gbps}
\]

A full batch of 64 reduces the theoretical receive syscall rate to:

\[
\frac{122070}{64}=1907\text{ syscalls/s}
\]

At 2 Gbps, it is approximately 3815 syscalls/s. [L3]

Use `recvmmsg` or `x/net/ipv4.PacketConn.ReadBatch` with a batch of 64 [UNVERIFIED batch choice]. Use `sendmmsg` on egress. Preallocate packet slabs, return them to a lane-local pool, and remove per-packet channel allocations.

Profile the installed binary:

```bash
PID=$(pidof winn3-gateway)

perf record -F 999 -g -p "$PID" -- sleep 30
perf report

perf lock record -p "$PID" -- sleep 30
perf lock report

nstat -az UdpRcvbufErrors UdpInErrors
ss -u -n -m -i | grep ':9111'
cat /proc/net/softnet_stat
cat /proc/net/sockstat
```

The sampling frequency and duration are [UNVERIFIED test parameters].

## 3. Stop the uplink session collapse

**The receive buffer failure is proven. The complete teardown chain is not.**

`udp_rcvbuf_errors: 96,200` proves that UDP packets reached a full receive socket and were discarded. [L1] It does not by itself prove whether the final teardown came from probe starvation, a fatal `ENOBUFS`, replay-window advancement, queue overflow or a blocked demux mutex.

Instrument every transition with monotonic timestamps and counters:

```text
kernel_receive
batch_read
session_lookup_start
session_lookup_end
aead_open_start
aead_open_end
authenticated_last_rx_update
control_dispatch
data_enqueue
tun_write
session_close_reason
```

Record queue occupancy in bytes, not merely packet count.

### Correct two-stage receive design

1. Each lane worker performs batched reads and AEAD authentication.
2. Immediately after successful authentication, update `lastAuthenticatedRx`.
3. Handle or coalesce liveness control before entering the data queue.
4. Enqueue ordinary data into a bounded, lane-local SPSC ring.
5. Route and write from the second stage.

A liveness timestamp must not wait behind TUN output or an overloaded data queue. Unauthenticated packets must not refresh it.

Treat these as nonfatal congestion events:

* Receive queue overflow.
* `EAGAIN`.
* Temporary `ENOBUFS`.
* Data ring overflow.
* A missed data enqueue.

They increment counters and mark the session degraded. They do not destroy keys or close the session.

The liveness deadline must exceed the measured maximum scheduler and queue stall by an explicit margin. The appropriate deadline is [UNVERIFIED] until those stalls are measured.

### Replace blind tail-drop

Do not put control and data in the same tail-drop channel.

For ordinary data, use drop-oldest on a bounded byte ring. Drop complete frames only:

```go
func enqueueData(q *SPSCRing, f *Frame) {
    for !q.TryPush(f) {
        old, ok := q.TryPop()
        if !ok {
            dataDropRace.Inc()
            f.Release()
            return
        }
        old.Release()
        dataDropOldest.Inc()
    }
}
```

Use a 4 MiB per-lane data-ring seed [UNVERIFIED]. Across four lanes:

\[
4\times4\text{ MiB}=16\text{ MiB}
\]

At 2 Gbps, a full aggregate ring represents:

\[
\frac{16\times2^{20}\times8}{2\times10^9}=0.0671\text{ s}
\]

That is still substantial queue latency. Reduce it if measured scheduling stalls do not require it.

Coalesce heartbeat state instead of queuing every heartbeat. Process authenticated close and rekey control messages through a separately bounded control path with per-peer rate limits [UNVERIFIED policy].

## 4. Suricata and TCP 443

**Accept TCP 443 before NFQUEUE.**

NFQUEUE 0 has already dropped 125,188 packets. [L1] Port 9111 bypasses NFQUEUE, so Suricata cannot explain Winn v3's port 9111 collapse. It can directly damage XRay on TCP 443.

For a direct authenticated XRay origin, insert the accept before the NFQUEUE rule:

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

Verify ordering:

```bash
iptables -nvL WINVPN-INPUT --line-numbers
ip6tables -nvL WINVPN-INPUT --line-numbers
```

This intentionally removes inline Suricata inspection from that service. TLS authentication and XRay access controls must remain enabled. Their adequacy for the threat model is [UNVERIFIED].

The rejected alternative is:

```bash
-j NFQUEUE \
  --queue-balance 0:5 \
  --queue-cpu-fanout \
  --queue-bypass
```

with Suricata attached to queues 0 through 5. The six queues correspond to the six vCPUs. This can distribute independent flows, but it retains userspace copying and queue reinjection. A single TCP flow can still remain concentrated on one CPU and queue. `--queue-bypass` also makes inspection fail open when no listener exists.

## 5. AWG MTU and MSS

**Use MTU 1440 only for a verified 1500 byte IPv4 outer path.**

Standard WireGuard data overhead is:

* Outer IPv4: 20 bytes.
* UDP: 8 bytes.
* WireGuard data header, counter and authentication tag: 32 bytes.

Therefore:

\[
1500-20-8-32=1440
\]

For an IPv6 outer path:

\[
1500-40-8-32=1420
\]

Whether the installed AmneziaWG data format adds bytes beyond standard WireGuard is [UNVERIFIED]. Confirm with packet capture.

IPv4 configuration:

```ini
[Interface]
MTU = 1440
```

An inner IPv4 TCP MSS of 1400 follows exactly:

\[
1440-20_{\text{IPv4}}-20_{\text{TCP}}=1400
\]

```bash
iptables -t mangle -I FORWARD 1 -i awg0 \
    -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1400

iptables -t mangle -I FORWARD 1 -o awg0 \
    -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1400
```

For inner IPv6 over MTU 1440, fixed MSS is 1380:

\[
1440-40_{\text{IPv6}}-20_{\text{TCP}}=1380
\]

**MTU 1408 and MSS 1400 are inconsistent.**

With MTU 1408:

\[
MSS_{IPv4}=1408-20-20=1368
\]

\[
MSS_{IPv6}=1408-40-20=1348
\]

If 1408 is needed after PMTU testing, use `--clamp-mss-to-pmtu` in both directions rather than retaining 1400:

```bash
iptables -t mangle -I FORWARD 1 -i awg0 \
    -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu

iptables -t mangle -I FORWARD 1 -o awg0 \
    -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu
```

Validate the outer IPv4 MTU:

```bash
ping -M do -s 1472 CANADA_VPS_IPV4
```

The resulting IP packet is:

\[
1472+8_{\text{ICMP}}+20_{\text{IPv4}}=1500
\]

Validate a 1440 byte inner IPv4 packet through AWG:

```bash
ping -I awg0 -M do -s 1412 INNER_PEER_IPV4
```

\[
1412+8+20=1440
\]

## 6. XRay Android pipe and direct transport

**A 4 KiB pipe causes excessive wake opportunities.**

At 1 Gbps:

\[
\frac{4096\times8}{10^9}=32.768\ \mu s
\]

If every fill causes a wake, the theoretical rate is approximately:

\[
\frac{10^9}{4096\times8}=30518\text{ wakes/s}
\]

A requested 4 MiB pipe holds:

\[
\frac{4\times2^{20}\times8}{10^9}=33.55\text{ ms at 1 Gbps}
\]

At the measured 1.6529 Gbps raw uplink:

\[
\frac{4\times2^{20}\times8}{1.6529\times10^9}=20.30\text{ ms}
\]

Attempt the Linux pipe resize and verify the result:

```c
int requested = 4 * 1024 * 1024; /* requested 4 MiB */
int result = fcntl(fd, F_SETPIPE_SZ, requested);
int actual = fcntl(fd, F_GETPIPE_SZ);

if (result < 0 || actual < requested) {
    /* Switch to a 4 MiB userspace byte ring or direct handoff. */
}
```

Android may reject this above `/proc/sys/fs/pipe-max-size` without the required capability. That result is [UNVERIFIED] on the S26 Ultra. Never report the requested value as effective without `F_GETPIPE_SZ`.

Better still, remove the intermediary pipe where XRay permits direct buffer ownership transfer. A large userspace copy buffer does not repair a kernel pipe that still wakes on 4 KiB writes.

### Remove Cloudflare from the data path

Use the direct origin IP while preserving the certificate hostname as TLS SNI:

```json
{
  "address": "DIRECT_ORIGIN_IP",
  "port": 443,
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "CERTIFICATE_HOSTNAME",
      "allowInsecure": false
    }
  }
}
```

Replace both placeholders with the deployed values. Direct routing removes the CDN hop by topology. Its throughput benefit remains [UNVERIFIED] until tested against the same origin, radio condition and stream count.

## 7. Android TUN pump

**`Thread.MAX_PRIORITY` does not prove that the Linux thread received useful scheduling priority.**

Set the Android process priority deliberately and inspect the resulting native thread:

```kotlin
Process.setThreadPriority(Process.THREAD_PRIORITY_DISPLAY)
```

Verify:

```bash
PID=$(adb shell pidof org.winsvpn.app.debug | tr -d '\r')
adb shell ps -T -p "$PID" -o PID,TID,PRI,NI,CLS,NAME
adb shell cat /proc/"$PID"/task/TUN_THREAD_TID/sched
```

Do not use real-time scheduling without starvation tests. Its safety is [UNVERIFIED].

### Burst-drain design

Use one blocking `poll` or `epoll` wake. Then drain the nonblocking TUN descriptor until `EAGAIN`, subject to a fairness budget:

```kotlin
while (running) {
    pollUntilReadable(tunFd)

    var packets = 0
    var bytes = 0

    while (packets < BURST_PACKETS && bytes < BURST_BYTES) {
        val buffer = packetPool.acquire()
        val n = tryReadNonBlocking(tunFd, buffer)

        if (n == EAGAIN) {
            packetPool.release(buffer)
            break
        }
        if (n <= 0) {
            packetPool.release(buffer)
            handleTunTermination(n)
            break
        }

        outboundQueue.enqueue(buffer, n)
        packets++
        bytes += n
    }

    transport.flushBatch()
}
```

`BURST_PACKETS` and `BURST_BYTES` must be selected from measured scheduler latency and UI fairness [UNVERIFIED]. A seed of 64 packets and 256 KiB is [UNVERIFIED], not a performance projection.

Use pooled direct buffers. Avoid one Kotlin object, coroutine launch or channel send per packet.

Bound the outbound queue by bytes. A 4 MiB bound represents 20.30 ms at the measured 1.6529 Gbps raw uplink. [L3] On overflow:

1. Preserve authenticated control separately.
2. Drop complete oldest data packets until the incoming packet fits.
3. Increment a visible counter.
4. Never partially overwrite an IP packet.
5. Do not terminate the VPN session.

## 8. S26 Ultra calculator lockout

**Clear the attempt state. Do not overwrite `user_pin.txt`.**

First stop the application and create a restricted local backup:

```bash
PKG=org.winsvpn.app.debug

adb shell am force-stop "$PKG"

umask 077
adb exec-out run-as "$PKG" sh -c 'tar -cf - .' \
    > winsvpn-private-backup.tar
```

`run-as` requires the installed package to be debuggable. That is [UNVERIFIED] despite the debug package name. If it fails, use a signed debug build with an app-internal reset action. Do not weaken device filesystem permissions.

Locate the state:

```bash
adb shell run-as "$PKG" sh -c \
  'find . -type f -maxdepth 4 -print'

adb shell run-as "$PKG" sh -c \
  'grep -R -n "pin_attempt_state" . 2>/dev/null'
```

Implement an authorized debug-only reset using the same storage API as `_readPinAttemptState()`:

```kotlin
fun clearPinAttemptStateForDebug(context: Context) {
    check(BuildConfig.DEBUG)

    val prefs = context.getSharedPreferences("vpn_settings", Context.MODE_PRIVATE)
    check(prefs.edit().remove("pin_attempt_state").commit())
}
```

If `vpn_settings.txt` is custom JSON or properties storage, parse it, remove only `pin_attempt_state`, write a temporary file, `fsync`, then atomically rename it. Do not use an unbounded `sed` expression against the credential file.

After clearing the state, invoke the actual verifier in an instrumentation test:

```kotlin
@Test
fun verifyAuthorizedPinAfterLockReset() {
    clearPinAttemptStateForDebug(targetContext)
    assertTrue(pinVerifier.verify("142536=".toCharArray()))
}
```

This verifies the supplied PIN through application code without rewriting or printing the stored credential.

### Repair the rollback bug

An `elapsedRealtime` deadline is valid only within the boot in which it was created. Store:

```text
bootCount
createdElapsedMs
lockDurationMs
failureCount
```

On read, clear the lock deadline if any invariant fails:

```kotlin
val invalid =
    state.bootCount != currentBootCount ||
    nowElapsedMs < state.createdElapsedMs ||
    state.lockDurationMs < 0 ||
    state.lockDurationMs > MAX_LOCKOUT_MS

if (invalid) {
    clearPinAttemptState()
}
```

`MAX_LOCKOUT_MS` is application policy [UNVERIFIED]. Authentication remains protected by the PIN; only the stale timer is discarded. This prevents a pre-reboot monotonic deadline from becoming a new future deadline after reboot.

## Acceptance gate

Do not declare success from a single speed result.

Run matched raw, Winn v3, AWG and XRay tests while collecting:

```bash
nstat -az UdpRcvbufErrors UdpInErrors
cat /proc/net/softnet_stat
cat /proc/interrupts
ss -u -n -m -i
pidstat -t -p "$(pidof winn3-gateway)" 1
```

The release gate is:

* Sustained throughput above 1 Gbps in the tested direction.
* No session teardown under offered overload.
* No increase in `UdpRcvbufErrors`.
* No NFQUEUE drop increase for direct TCP 443.
* No continuously growing userspace queue.
* No single global demux lock dominating the `perf` profile.
* Effective Android pipe or ring capacity verified at runtime.
* PIN verification succeeds after clearing only `pin_attempt_state`.

The raw handset path at 1.7427 Gbps and the VPS result near 1.96 Gbps prove that the network can exceed 1 Gbps under the recorded conditions. [L1] They do not guarantee identical capacity at another time, under another provider load or with a different packet-size distribution.