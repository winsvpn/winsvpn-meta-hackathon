# Stage 3 Synthesis: stage3_sol_pro

# Stage 3: Consensus specification and unanimous position lock

## 1. Final ruling

**The specification is locked.**

The lock contains runtime branches for path MTU, address family, GSO capability, and Double VPN return routing. Those branches resolve missing deployment facts. They are not unresolved technical disagreements.

Three findings govern the result:

1. **UDP GSO and GRO must operate symmetrically.**
   * Upload: handset GSO, aicore GRO.
   * Download: aicore GSO, handset GRO.

2. **The Go engine must own the Android TUN descriptor directly.**
   A Kotlin `LocalSocket` packet relay remains prohibited unless profiling proves that direct ownership is impossible on the target build.

3. **Double VPN uses terminated tunnels, not stacked encapsulation.**
   Hop 1 headers are removed at aicore before Hop 2 is applied. The usable inner MTU is therefore the minimum MTU supported by either hop, not the result of subtracting both tunnels' overhead from one packet.

A literal 2.00 Gbps application payload target is not accepted for a 2.00 Gbps Ethernet service.

---

## 2. Explicit concessions and reconciled disputes

### 2.1 Podium 2 concessions

I accept the following defects in my earlier implementation:

* `UDP_SEGMENT` transmit ancillary data is a native endian `uint16`, exactly 2 bytes.
* `UDP_GRO` receive ancillary data is a native endian Linux `int`, exactly 4 bytes.
* `WriteMsgUDP` returns three values: payload bytes, ancillary bytes, and error.
* A receive callback must not retain a slice backed by a reusable GRO buffer.
* `EINVAL` must not be treated as a generic indication that GSO is unsupported.
* My earlier 1.899 Gbps figure omitted Winn and UDP overhead. It was not a Winn VPN ceiling.

These corrections are accepted without reservation.

### 2.2 Ceiling arithmetic

Assume:

* Inner MTU: 1373 bytes.
* Winn record overhead: 32 bytes.
* Outer IPv4: 20 bytes.
* UDP: 8 bytes.
* Ethernet line overhead without VLAN: 38 bytes.
* Inner TCP data without options: \(1373-20-20=1333\) bytes.

Then:

\[
S_{\text{outer IP}}=1373+32+8+20=1433
\]

\[
S_{\text{wire}}=1433+38=1471
\]

\[
PPS=\frac{2\times10^9}{1471\times8}=169,952
\]

\[
T_{\text{TCP}}=169,952\times1333\times8
=1.8126\text{ Gbps}
\]

Podium 3's 1.8126 Gbps result is accepted under those assumptions.

At inner MTU 1440, the outer IPv4 packet occupies the full 1500 bytes:

\[
T_{\text{TCP}}
=
2\times10^9\times\frac{1400}{1538}
=
1.8205\text{ Gbps}
\]

The gain from 1373 to 1440 is about 7.9 Mbps under this wire accounting. Raising MTU may reduce packet rate, but it does not turn a 2 Gbps Ethernet service into 2 Gbps of application payload.

The 1.5 Gbps target consumes:

\[
\frac{1.5}{1.8126}=82.75\%
\]

of the calculated ceiling. Arithmetic does not rule it out. CPU and scheduler measurements must still prove it.

### 2.3 Socket buffers

Podium 4's clamp and doubling correction is accepted.

Linux performs the effective operation:

\[
\text{stored buffer}
=
2\times\min(\text{requested buffer},\text{sysctl maximum})
\]

subject to kernel minimums. Therefore, if Android has an 8 MiB `rmem_max`, requests for both 8 MiB and 16 MiB produce a reported `SO_RCVBUF` of 16 MiB.

The 40 ms payload burst at 2 Gbps is:

\[
2\times10^9\times0.040/8=10,000,000\text{ bytes}
\]

A 16 MiB request exceeds that payload count, but skb `truesize` accounting prevents claiming 40 ms of guaranteed absorption. Effective sizes and drop counters must be measured.

### 2.4 NAT and conntrack

Neither universal NAT-free routing nor universal SNAT is accepted.

The deterministic rule is:

* Use pure routing if the selected exit has a route back to the handset prefix and permits that source prefix.
* Use explicit SNAT to the aicore Hop 2 address if the exit does not have that route.
* Use MASQUERADE only when the Hop 2 source address is genuinely dynamic.

A `/32` address alone does not prove MASQUERADE failure. That claim was not demonstrated.

Conntrack table occupancy scales primarily with concurrent tracked flows, not packet rate. Sixteen TCP streams create approximately sixteen TCP conntrack entries, not 170,000 entries per second. Packet rate still affects lookup CPU cost, but that cost requires `perf` or `simpleperf` evidence.

### 2.5 FQ pacing

Podium 4's qualification is accepted.

FQ can classify forwarded traffic, but socket pacing information exists only for locally generated socket traffic. Therefore:

* FQ on tunnel devices supplies bounded per-flow queues.
* FQ on the physical egress can pace local Winn UDP traffic when the socket provides pacing metadata.
* FQ alone is not an aggregate rate shaper across several outer UDP flows.

An aggregate cap requires a classful parent such as HTB, or another explicit shaper, with FQ below it.

### 2.6 Wake locks and threading

Accepted:

* A partial wake lock prevents suspend. It does not fix CPU frequency or scheduler placement.
* Parallel TUN writers can reorder packets.
* If parallel writers are introduced, inner flows must be assigned consistently to one writer, or a sequence reorder stage must restore order.

---

# 3. Locked UDP GSO and GRO specification

## 3.1 Linux ancillary data ABI

The Linux ABI requires:

| Operation | Level | Type | Payload |
|---|---:|---:|---:|
| GSO transmit | `SOL_UDP` | `UDP_SEGMENT` | native endian `uint16`, 2 bytes |
| GRO receive | `SOL_UDP` | `UDP_GRO` | native endian `int`, 4 bytes |

Linux UAPI values are:

```go
const (
    solUDP     = 17
    udpSegment = 103
    udpGRO     = 104
)
```

Use the `x/sys/unix` constants when the selected version exports them. The numeric definitions may be retained behind a Linux build tag for older module versions.

## 3.2 Transmit cmsg construction

```go
//go:build linux

package fastudp

import (
    "encoding/binary"
    "fmt"
    "net"
    "unsafe"

    "golang.org/x/sys/unix"
)

const (
    solUDP          = 17
    udpSegment      = 103
    udpGRO          = 104
    maxGSOSegments  = 64
    maxGSOAggregate = 60 * 1024
)

func segmentCmsg(segmentSize int) ([]byte, error) {
    if segmentSize <= 0 || segmentSize > 65535 {
        return nil, fmt.Errorf("invalid UDP_SEGMENT size %d", segmentSize)
    }

    oob := make([]byte, unix.CmsgSpace(2))
    hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
    hdr.Level = int32(solUDP)
    hdr.Type = int32(udpSegment)
    hdr.SetLen(unix.CmsgLen(2))

    off := unix.CmsgLen(0)
    binary.NativeEndian.PutUint16(
        oob[off:off+2],
        uint16(segmentSize),
    )
    return oob, nil
}

func writeGSO(
    c *net.UDPConn,
    dst *net.UDPAddr,
    aggregate []byte,
    segmentSize int,
) error {
    if len(aggregate) == 0 {
        return fmt.Errorf("empty GSO aggregate")
    }
    if len(aggregate)%segmentSize != 0 {
        return fmt.Errorf("aggregate is not an exact segment multiple")
    }

    segments := len(aggregate) / segmentSize
    if segments < 2 || segments > maxGSOSegments {
        return fmt.Errorf("invalid GSO segment count %d", segments)
    }
    if len(aggregate) > maxGSOAggregate {
        return fmt.Errorf("GSO aggregate exceeds 60 KiB")
    }

    oob, err := segmentCmsg(segmentSize)
    if err != nil {
        return err
    }

    n, oobn, err := c.WriteMsgUDP(aggregate, oob, dst)
    if err != nil {
        return err
    }
    if n != len(aggregate) || oobn != len(oob) {
        return fmt.Errorf(
            "short GSO write: payload %d/%d, oob %d/%d",
            n, len(aggregate), oobn, len(oob),
        )
    }
    return nil
}
```

The 60 KiB aggregate limit leaves space below the 65,535 byte non-jumbo IP size limit:

\[
61,440+8+40=61,488<65,535
\]

It is valid for both ordinary IPv4 and IPv6 outer headers.

## 3.3 Segment validation

Before batching, enforce:

\[
S_{\text{record}}+8+H_{\text{outer IP}}\le PMTU
\]

`S_record` is the complete encrypted UDP payload for one Winn record. It is not the inner MTU.

For a 1500 byte PMTU and outer IPv4:

\[
S_{\text{record}}\le1500-20-8=1472
\]

For outer IPv6:

\[
S_{\text{record}}\le1500-40-8=1452
\]

Every record in the locked baseline batch must have exactly the same encrypted length. A change in record length flushes the current batch. This prevents the kernel from dividing the aggregate through a record boundary.

The batch count is:

\[
N=
\min\left(
64,
\left\lfloor\frac{61,440}{S_{\text{record}}}\right\rfloor
\right)
\]

At 1405 bytes per encrypted record:

\[
N=\left\lfloor\frac{61,440}{1405}\right\rfloor=43
\]

## 3.4 AEAD ordering

Each inner packet must be encrypted separately:

```text
inner packet 1 -> header 1 || AEAD.Seal(packet 1)
inner packet 2 -> header 2 || AEAD.Seal(packet 2)
inner packet 3 -> header 3 || AEAD.Seal(packet 3)

GSO aggregate = record 1 || record 2 || record 3
```

Each record receives its own sequence number, nonce, authentication tag, and replay check.

Encrypting the aggregate with one AEAD operation is prohibited because a GRO receiver must authenticate and deliver the resulting UDP datagrams independently.

## 3.5 GRO enablement and parsing

```go
func setUDPGRO(c *net.UDPConn, enabled bool) error {
    raw, err := c.SyscallConn()
    if err != nil {
        return err
    }

    value := 0
    if enabled {
        value = 1
    }

    var sockErr error
    if err := raw.Control(func(fd uintptr) {
        sockErr = unix.SetsockoptInt(
            int(fd),
            solUDP,
            udpGRO,
            value,
        )
    }); err != nil {
        return err
    }
    return sockErr
}

func groSegmentSize(oob []byte, payloadLen int) (int, error) {
    messages, err := unix.ParseSocketControlMessage(oob)
    if err != nil {
        return 0, err
    }

    found := false
    size := 0

    for _, message := range messages {
        if message.Header.Level != int32(solUDP) ||
            message.Header.Type != int32(udpGRO) {
            continue
        }

        if found {
            return 0, fmt.Errorf("duplicate UDP_GRO cmsg")
        }
        found = true

        if len(message.Data) != 4 {
            return 0, fmt.Errorf(
                "UDP_GRO cmsg has %d bytes, expected 4",
                len(message.Data),
            )
        }

        value := binary.NativeEndian.Uint32(message.Data)
        if value == 0 || value > 65535 {
            return 0, fmt.Errorf("invalid GRO segment size %d", value)
        }
        size = int(value)
    }

    if !found {
        return 0, nil
    }
    if size > payloadLen {
        return 0, fmt.Errorf("GRO segment exceeds payload")
    }
    if payloadLen%size != 0 {
        return 0, fmt.Errorf("GRO payload is not an exact segment multiple")
    }
    if payloadLen/size > maxGSOSegments {
        return 0, fmt.Errorf("GRO aggregate exceeds segment cap")
    }

    return size, nil
}
```

The receive loop must also reject `MSG_TRUNC` and `MSG_CTRUNC`.

Each returned segment is independently parsed, replay-checked, and authenticated. Authentication failure for one segment does not turn the complete aggregate into one ciphertext.

The segment slice is borrowed memory. A synchronous consumer may use it until the callback returns. An asynchronous consumer must copy it into an owned buffer before enqueueing it.

## 3.6 Error policy

The locked policy is:

* `ENOPROTOOPT` or `EOPNOTSUPP`: disable the relevant offload, record a capability metric, then send or receive individual datagrams.
* `EMSGSIZE`: split the batch while preserving order. If a one-segment send still returns `EMSGSIZE`, reduce the tunnel MTU or repair PMTU discovery.
* `EINVAL`: configuration or ABI error. Log the validated segment size, aggregate size, cmsg width, and address family. Do not silently disable GSO.
* Partial or ambiguous writes: do not reseal with a new nonce. Retain the already sealed records and either retry those exact bytes according to the transport policy or fail the session.

No feature path depends on NIC hardware GSO. Software segmentation still removes userspace send calls, which is verified by syscall counts rather than an assumed hardware capability.

---

# 4. Locked socket buffer specification

Both handset and aicore request:

```go
const socketBuffer = 16 * 1024 * 1024

unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, socketBuffer)
unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, socketBuffer)
```

Immediately read back:

```go
rx, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
tx, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
```

Log requested and reported values.

On aicore, in the same network namespace as the daemon:

```bash
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

Persistence must be configured through the host's sysctl mechanism.

Do not change global `udp_mem` without observing global UDP memory pressure. Required counters are:

```bash
nstat -az | grep -E 'Udp.*Errors|RcvbufErrors|SndbufErrors'
ss -u -m -n
```

Enable and parse `SO_RXQ_OVFL` where supported. The Winn engine's own drop counter cannot observe datagrams discarded before userspace receives them.

On Android, the app normally cannot raise `rmem_max` or `wmem_max`. Verify the deployed values and effective socket sizes:

```bash
adb shell cat /proc/sys/net/core/rmem_max
adb shell cat /proc/sys/net/core/wmem_max
```

---

# 5. Locked Android mobile fast path

## 5.1 Descriptor ownership

Kotlin establishes the TUN and transfers sole ownership to Go:

```kotlin
val pfd = vpnBuilder.establish()
    ?: error("VpnService.Builder.establish returned null")

val tunFd = pfd.detachFd()
var transferred = false

try {
    nativeStart(tunFd)
    transferred = true
} finally {
    pfd.close()
    if (!transferred) {
        android.system.Os.close(tunFd)
    }
}
```

After `detachFd()`, the `ParcelFileDescriptor` no longer owns the raw descriptor. Go closes it exactly once after all packet loops have stopped.

`ParcelFileDescriptor.adoptFd(tunFd)` must not be used merely to obtain a `FileDescriptor`. `adoptFd` creates ownership, so a close or cleaner action can terminate the descriptor while Go is still using it.

If both runtimes need independent ownership, call `dup` and assign one descriptor to each owner.

The outer UDP socket must be protected with `VpnService.protect(fd)` before it sends traffic. Otherwise its packets can route back into the VPN TUN. Protection success is a connection prerequisite.

## 5.2 Nonblocking setup

Go preserves the existing descriptor flags:

```go
flags, err := unix.FcntlInt(
    uintptr(tunFD),
    unix.F_GETFL,
    0,
)
if err != nil {
    return err
}

_, err = unix.FcntlInt(
    uintptr(tunFD),
    unix.F_SETFL,
    flags|unix.O_NONBLOCK,
)
```

The broken sequence of detaching a `ParcelFileDescriptor` and then reading its invalid `fileDescriptor` is removed.

## 5.3 Packet loops

Use `epoll` with:

* TUN descriptor.
* UDP descriptor.
* `eventfd` or pipe for shutdown.
* `timerfd` only if a measured batching deadline is required.

The upload loop is:

1. Drain TUN reads until `EAGAIN`.
2. Treat each successful read as one complete inner packet.
3. Seal each packet into an independent Winn record.
4. Batch equal-length records.
5. Flush at the batch limit or when the TUN drain reaches `EAGAIN`.
6. Submit through UDP GSO when available.

The download loop is:

1. Drain UDP `ReadMsgUDP` calls until `EAGAIN`.
2. Reject truncated payload or ancillary data.
3. Split using validated `UDP_GRO`.
4. Authenticate each record separately.
5. Write one complete inner packet per TUN write.

A TUN write that returns `EAGAIN` retains that packet until `EPOLLOUT`. A nonzero short TUN write is treated as an error. The remainder must not be written as another packet because each TUN write represents a separate packet.

The baseline uses one TUN reader and one TUN writer. Parallel writers are permitted only after profiling and with deterministic flow assignment. TCP and UDP packets use an inner 5-tuple hash. IP fragments use source, destination, protocol, and fragment identifier so fragments from one datagram remain on one writer.

## 5.4 Wake lock

The VPN service holds an untimed partial wake lock only while the data plane is active:

```kotlin
wakeLock.setReferenceCounted(false)
wakeLock.acquire()

try {
    runVpn()
} finally {
    if (wakeLock.isHeld) {
        wakeLock.release()
    }
}
```

No timeout is supplied. Stop, error, and service destruction paths must all reach `release()`.

The wake lock prevents suspend. CPU frequency claims require separate evidence from frequency residency, scheduler placement, and thermal status.

---

# 6. Locked Double VPN routing on aicore

## 6.1 Exit table allocation

| Exit | Table | Packet mark | Logical device |
|---|---:|---:|---|
| Kansas Core | 201 | `0x201` | `exit-kansas` |
| Canada ca1 | 202 | `0x202` | `exit-ca1` |
| Germany de1 | 203 | `0x203` | `exit-de1` |
| Spain | 204 | `0x204` | `exit-spain` |

Actual endpoint addresses come from the control plane or DNS. They are not embedded permanently in the routing script.

Each table receives a default route through its corresponding Hop 2 interface, including the measured interface MTU:

```bash
ip route replace table 201 default dev exit-kansas mtu "$KANSAS_MTU"
ip route replace table 202 default dev exit-ca1    mtu "$CA1_MTU"
ip route replace table 203 default dev exit-de1    mtu "$DE1_MTU"
ip route replace table 204 default dev exit-spain  mtu "$SPAIN_MTU"
```

If an interface requires a peer gateway, the route uses `via PEER dev DEVICE` instead of a device-only default.

Rules are installed with explicit priorities:

```bash
ip rule add pref 1201 fwmark 0x201/0xfff lookup 201
ip rule add pref 1202 fwmark 0x202/0xfff lookup 202
ip rule add pref 1203 fwmark 0x203/0xfff lookup 203
ip rule add pref 1204 fwmark 0x204/0xfff lookup 204
```

An nftables map assigns the selected mark to packets entering from `winn3gw0`. Updating the client's selected exit is one atomic map update, not a sequence of deleting and reinserting policy rules.

## 6.2 Dynamic underlay lookup

A dedicated underlay table contains the physical WAN routes and default gateway. Outer tunnel sockets receive an underlay mark such as `0x10000`.

```bash
ip rule add pref 100 fwmark 0x10000/0x10000 lookup 100
```

For every resolved Kansas, ca1, de1, or Spain endpoint:

```bash
ip -j route get "$ENDPOINT" mark 0x10000
```

The controller extracts and records:

* Output device.
* Gateway, if present.
* Preferred source.
* Route MTU.
* Address family.

The lookup must resolve to a physical underlay device. Resolution to `winn3gw0` or any `exit-*` device fails closed because it indicates tunnel recursion.

DNS or control-plane address changes trigger a fresh lookup before reconnecting. Old host routes are removed only after the sessions using them have drained.

Userspace outer sockets set `SO_MARK=0x10000`. Kernel tunnel implementations use the corresponding firewall mark facility.

## 6.3 Routing and SNAT branch

For each exit, the control plane declares one of two modes.

### Routed mode

The remote exit must have a return route for the handset prefix:

```bash
ip route get 10.10.0.14
```

must resolve through the Hop 2 tunnel on that exit.

No SNAT is applied on aicore.

### SNAT mode

If the remote exit does not route the handset prefix, aicore translates to its stable Hop 2 inner address:

```text
oifname exit-ca1
ip saddr 10.10.0.0/24
snat to CA1_AICORE_INNER_ADDRESS
```

This mode requires conntrack.

MASQUERADE is reserved for dynamically assigned Hop 2 addresses. Pure routed traffic may bypass conntrack only if the firewall policy does not require stateful inspection.

## 6.4 Reverse path filtering

Serial tunnels are legitimately asymmetric. Configure:

```bash
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.winn3gw0.rp_filter=0
sysctl -w net.ipv4.conf.exit-kansas.rp_filter=0
sysctl -w net.ipv4.conf.exit-ca1.rp_filter=0
sysctl -w net.ipv4.conf.exit-de1.rp_filter=0
sysctl -w net.ipv4.conf.exit-spain.rp_filter=0
```

Linux uses the maximum of the `all` and per-interface reverse path settings, so setting only the tunnel interface is insufficient when `all` remains strict.

## 6.5 TCPMSS and PMTU

Install clamping in both directions for every selected exit:

```bash
iptables -t mangle -A FORWARD \
  -i winn3gw0 -o "$EXIT_DEV" \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

iptables -t mangle -A FORWARD \
  -i "$EXIT_DEV" -o winn3gw0 \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
```

Install equivalent IPv6 rules with `ip6tables`, or use an nftables ruleset with the same semantics.

At an inner MTU of 1373:

\[
MSS_{\text{IPv4}}=1373-20-20=1333
\]

\[
MSS_{\text{IPv6}}=1373-40-20=1313
\]

TCPMSS applies only to TCP. ICMP fragmentation-needed and IPv6 packet-too-big messages must remain permitted so UDP and other protocols can discover PMTU.

## 6.6 FQ queueing and pacing

FQ is attached to:

* `winn3gw0`.
* Each active `exit-*` device.
* Every physical underlay device returned by the endpoint route lookups.

Queue size is calculated from a selected maximum queue delay:

\[
N=
\left\lceil
\frac{R\times Q}{8S}
\right\rceil
\]

For \(R=2\) Gbps, \(Q=10\) ms, and \(S=1471\) wire bytes:

\[
N=
\left\lceil
\frac{2\times10^9\times0.010}{8\times1471}
\right\rceil
=1700
\]

That replaces the unbounded 32,768 packet proposal.

Example:

```bash
tc qdisc replace dev "$DEV" root fq \
  limit 1700 \
  flow_limit 512 \
  quantum 1514 \
  pacing
```

The actual limit is recalculated when the measured service rate or queue-delay target changes.

For local Winn UDP sockets, set `SO_MAX_PACING_RATE` in bytes per second. If several outer sockets share one WAN:

\[
\sum_i R_i \le R_{\text{measured egress}}
\]

FQ statistics must be inspected:

```bash
tc -s qdisc show dev "$DEV"
```

If a hard aggregate WAN cap is needed, use an aggregate parent shaper with FQ beneath it. FQ's per-flow `maxrate` is not a substitute for a multi-flow aggregate cap.

---

# 7. Locked ingress multiprotocol demux on aicore

## 7.1 Transport split

TCP and UDP may use the same numeric port because the kernel socket namespaces include the transport protocol.

The UDP ingress handles:

* Winn v3.
* Winn v1 AWG.
* Explicitly configured XRay UDP fallback.

The TCP ingress handles XRay and any defined Winn TCP handshake.

## 7.2 UDP decision order

Every GRO aggregate is split into its original UDP datagrams before protocol classification.

Classification then follows:

1. Existing authenticated session mapping.
2. Exact Winn v3 public version and header discriminator.
3. Exact configured AWG `H1` through `H4` discriminator and valid size class.
4. Explicit XRay UDP discriminator, if configured.
5. Unknown packet drop.

Winn v3 packets undergo AEAD authentication.

AWG packets undergo the AWG handshake MAC or transport authentication checks. AWG junk packets are discarded according to AWG configuration. They are not sent to XRay.

A packet that matches a Winn or AWG discriminator but fails authentication is dropped. It is not tried against another parser.

The acceptance probability of trying two independent parsers is bounded by:

\[
P(A\cup B)\le P(A)+P(B)
\]

Prohibiting fallback after a claimed protocol match prevents the authentication surface from becoming the union of all protocol parsers.

If Winn and AWG discriminator sets overlap, startup fails and the protocols must use separate ports. Guessing between overlapping formats is prohibited.

## 7.3 Implementation options

Preferred UDP implementation:

* One ingress process owns the UDP socket.
* `recvmmsg` or UDP GRO receives batches.
* Protocol handlers run as in-process modules.
* An authenticated session cache gives constant-time dispatch after the first packet.

A `SO_REUSEPORT` eBPF selector is permitted when all clear discriminators are exact and disjoint. Authentication still occurs in the selected userspace handler.

Relaying every UDP datagram through a Unix socket is not accepted because it recreates the copy and syscall path removed from the handset.

For TCP fallback to an external XRay process:

1. Inspect with `MSG_PEEK`, so no application bytes are consumed.
2. Pass the accepted descriptor with `SCM_RIGHTS`.
3. Close the dispatcher copy after the receiver acknowledges ownership.

## 7.4 Required demux tests

The release gate contains:

* Valid Winn v3 fixtures.
* Valid Winn v1 AWG fixtures for every configured `H1` through `H4`.
* Valid XRay fallback fixtures.
* Truncated headers.
* Wrong versions.
* Authentication failures.
* Replay attempts.
* Discriminator collisions.
* GRO aggregates containing multiple valid records.
* Fuzzing of every unauthenticated parser.

Counters are required for protocol selection, unknown packets, authentication failures, replay drops, and malformed packets. Per-packet error logging is prohibited under load. Counters and rate-limited diagnostic logs provide the evidence.

---

# 8. Acceptance gates

The release is approved only after all of these pass:

1. WAN counters and packet capture prove the benchmark crossed the public interface.
2. `simpleperf` shows direct TUN ownership and GSO or GRO reduce syscall count and CPU cycles.
3. Upload and download both exercise their correct GSO and GRO endpoints.
4. `getsockopt` reports effective socket buffer sizes.
5. `SO_RXQ_OVFL`, `nstat`, and softnet counters show no unexplained drops.
6. Packet capture proves no outer fragmentation.
7. Each Double VPN exit shows the expected public exit address.
8. `ip route get` proves every outer endpoint remains on the physical underlay.
9. Routed exits prove their return route. Other exits use explicit SNAT.
10. `tc -s qdisc` proves queue limits and pacing are active on the actual egress devices.
11. A thermal-duration test reports throughput, CPU frequency residency, and thermal status.

## 9. Position lock

No normative technical disagreement remains.

The remaining unknowns are measurements:

* Actual Winn record overhead.
* Outer IPv4 or IPv6 selection.
* PMTU for each endpoint.
* Provider shaping domain.
* Android kernel offload support.
* Return-route capability for each Double VPN exit.

Each unknown has a defined measurement and a deterministic configuration branch.

**Final vote: YES. Adopt and ship this consensus specification. Do not advertise 2.00 Gbps of application payload on a 2.00 Gbps Ethernet service.**
