# Turn 1 Submission: solpro

**1. Arithmetic audit**

Several docket throughput and packet rate values use incompatible denominators.

For 1,373 byte inner packets:

\[
\text{bits per packet}=1373 \times 8=10,984
\]

\[
\text{pps at 1 Gbps}=\frac{1,000,000,000}{10,984}=91,041.515
\]

\[
\text{budget}=\frac{1,000,000}{91,041.515}=10.984\ \mu s
\]

Applying the same packet size to the reported measurements:

| Measurement | Computed pps | Computed time per packet |
|---|---:|---:|
| 426.0 Mbps | 38,783.685 | 25.784 µs |
| 883.3 Mbps | 80,416.970 | 12.435 µs |
| 1,000 Mbps | 91,041.515 | 10.984 µs |

The reported 31,026 pps corresponds to:

\[
31,026 \times 10,984=340,789,584\ \text{bps}=340.790\ \text{Mbps}
\]

It does not correspond to 426 Mbps. Likewise, 32.23 µs is the reciprocal of approximately 31,026 pps, not 38,784 pps.

Consequently:

- The sustained gap from 426 Mbps is \(25.784-10.984=14.800\ \mu s\).
- The engine peak gap from 883.3 Mbps is \(12.435-10.984=1.451\ \mu s\).
- The claimed 21.25 µs gap mixes the 31,026 pps counter with the 426 Mbps throughput counter.

Any Stage C benchmark must report inner bytes, outer bytes, packet count, interval, and CPU time from the same measurement window. Otherwise an exact expected throughput cannot be derived.

**2. OI-1: Super-frame architecture**

Mechanism A

The shown packing condition contains a dimensional contradiction. With `budget == 1373` and `len(p) == 1373`:

```text
0 + 3 + 1373 > 1373
1376 > 1373
```

The packet cannot be appended at all. Either `maxPayload()` is not actually 1,373, the packet is smaller than 1,373, or `MaxMessageSize` has been described incorrectly.

For two full packets, the plaintext alone is:

\[
2 \times (1373+3)=2752\ \text{bytes}
\]

For four:

\[
4 \times (1373+3)=5504\ \text{bytes}
\]

A 1,500 byte IPv4 path permits at most 1,472 bytes of UDP payload. IPv6 permits at most 1,452 bytes without extension headers. Therefore:

- Two or four full-size frames cannot occupy one ordinary path-MTU-sized UDP datagram.
- They require a jumbo path, outer IP fragmentation, or protocol-level segmentation and reassembly.
- `UDP_SEGMENT` cannot segment one AEAD message into independently received pieces. Each emitted UDP segment must already be a complete Winn message with its own header, nonce, ciphertext, and authentication tag.
- Mechanism A remains useful for small inner packets whose aggregate still fits the existing payload budget.

If \(C_A\) is the fixed per-message cost of AEAD setup, message construction, and fixed outer processing, packing \(N\) frames retires:

\[
\Delta T_A=C_A\left(1-\frac{1}{N}\right)
\]

Thus N = 2 retires 50 percent of \(C_A\), while N = 4 retires 75 percent. The value of \(C_A\) is not provided, so converting those percentages into microseconds would be fabricated.

At the target packet rate:

| Frames per message | Messages per second | AEAD operations retired per second |
|---:|---:|---:|
| 1 | 91,041.515 | 0 |
| 2 | 45,520.757 | 45,520.757 |
| 4 | 22,760.379 | 68,281.136 |

Mechanism B

`UDP_SEGMENT` should concatenate complete, independently authenticated outer datagrams. It amortizes sender kernel work but does not reduce:

- AEAD operations
- Protocol headers
- Receiver datagram count
- Gateway decryption operations
- Gateway TUN writes

Current carrier occupancy is:

\[
\frac{1,811,929}{1,146,349}=1.580612\ \text{datagrams per call}
\]

Current calls per datagram are:

\[
\frac{1,146,349}{1,811,929}=0.632668
\]

With G = 16 equal-sized UDP segments:

\[
\text{new calls per datagram}=\frac{1}{16}=0.0625
\]

At 91,041.515 packets per second:

- Current occupancy predicts about 57,599 send calls per second.
- G = 16 predicts 5,690 send calls per second.
- Reduction is about 51,909 calls per second.
- Per-packet reduction is \(0.632668-0.0625=0.570168\) send entries.

If one send entry costs \(S\) microseconds, the exact syscall-related retirement is:

\[
\Delta T_B=0.570168S\ \mu s/\text{packet}
\]

Additional pre-segmentation kernel savings require a handset measurement. They cannot be calculated from packet counters.

GSO also requires equal segment sizes except for the final segment. Variable-sized Winn datagrams must be grouped by equal wire length or padded using a protocol-defined authenticated padding frame.

Mechanism C

The existing JNI method already batches the JNI transition, but its loop still performs one `read()` per packet. Therefore its TUN syscall retirement is exactly zero.

At the target rate, TUN read CPU consumption is:

\[
91,041.515 \times 2.0\ \mu s=182.083\ \text{ms/core-second}
\]

to:

\[
91,041.515 \times 4.5\ \mu s=409.687\ \text{ms/core-second}
\]

That is 18.2 to 41.0 percent of one CPU core. It does not prevent 1 Gbps by itself. At the target, the remaining budget after TUN read is:

- 8.984 µs when read costs 2.0 µs
- 6.484 µs when read costs 4.5 µs

An IPC batch opcode could amortize framing and wakeups, but `allocPacket(payload)` and packet ownership remain per-packet unless the ring accepts slab references. The 16 byte IPC header consumes only:

\[
91,041.515 \times 16=1,456,664\ \text{bytes/s}
\]

That is approximately 11.65 Mbps of memory traffic. Allocation and wakeup costs are more credible targets than header bandwidth.

Architectural selection

- Mechanism A has the greatest theoretical fixed-cost reduction, but it is unavailable for multiple 1,373 byte packets over an ordinary 1,500 byte path.
- Mechanism B is the strongest immediately feasible sender optimization, subject to a real routed-socket probe and equal-length grouping.
- Mechanism C should target IPC ownership and allocation. Rewriting the existing JNI loop alone will not remove TUN reads.
- The deployable combination is B plus a separately profiled transmit-only IPC ownership change. Outer IP fragmentation should not be used.

Vote OI-1: `DISAGREE: two 1,373-byte frames require at least 2,752 plaintext bytes, which exceeds the 1,472-byte IPv4 UDP payload available on a standard 1,500-byte path.`

**3. OI-2: Android and kernel capabilities**

UDP segmentation

Upstream Linux supports `UDP_SEGMENT` without `CAP_NET_ADMIN`. Kernel version 6.12 makes support likely, but it does not prove that Samsung's socket policy, vendor networking hooks, checksum path, or Wi-Fi route accepts the operation.

The decisive probe is:

1. Use the actual connected production carrier socket.
2. Construct two complete, equal-sized, independently authenticated Winn datagrams.
3. Submit one `sendmsg` with `SOL_UDP/UDP_SEGMENT`.
4. Treat `ENOPROTOOPT`, `EOPNOTSUPP`, `EINVAL`, or policy-related `EPERM` as unsupported.
5. Fall back to the existing `sendmmsg` path without dropping either datagram.

TUN behavior

A normal TUN read dequeues one skb. `readv()` changes destination layout, not dequeue cardinality. `IFF_VNET_HDR` prepends virtio metadata to a packet and is not inherently a multi-packet read API.

Android `VpnService.Builder.establish()` does not expose creation-time `IFF_VNET_HDR`, `IFF_MULTI_QUEUE`, or TUN offload negotiation. Flags should still be checked with `TUNGETIFF` on the retail device rather than inferred from kernel version.

`io_uring` could batch submission of several read operations, if permitted by Android policy, but each completion still corresponds to an skb. It may amortize syscall entry but does not convert the TUN stream into a packet batch.

TUN-only ceiling

If TUN read were the only cost, the arithmetic ceiling would be:

| Read cost | Packet ceiling | Inner throughput ceiling |
|---:|---:|---:|
| 2.0 µs | 500,000 pps | 5.492 Gbps |
| 4.5 µs | 222,222.222 pps | 2.441 Gbps |

These are upper bounds, not end-to-end predictions. The exact maximum with crypto, IPC, scheduling, carrier output, and gateway processing cannot be calculated from the provided data.

Vote OI-2: `DISAGREE: Linux 6.12 support alone does not prove that a UDP_SEGMENT send on the handset's actual Wi-Fi-routed socket succeeds.`

**4. OI-3: Gateway ingress and demultiplexing**

Datagram truncation

A receive iovec of 2,048 bytes cannot hold a 2,752 byte two-frame plaintext, even before adding the Winn transport header and AEAD tag. At least 704 bytes would be absent from the userspace buffer.

The effect depends on the `recvmmsg` flags and validation path, but the entire datagram is not available to the parser. The message must be rejected.

This distinction matters:

- Mechanism B does not require a larger gateway buffer. The sender kernel emits ordinary UDP datagrams no larger than the configured GSO segment size.
- Mechanism A using oversized UDP datagrams does require a larger buffer and would also invoke IP fragmentation on a normal path.

Multi-frame delivery

`core.ParseFrames` proves only that plaintext parsing supports multiple frames. End-to-end support additionally requires the receive call site to:

1. Iterate every returned `FrameData`.
2. Preserve each frame's lifetime after the decrypted plaintext buffer is reused.
3. Queue each inner packet independently.
4. Perform one TUN write per inner packet.

A TUN write represents one packet. Writing concatenated inner packets in one `write()` is not a valid substitute.

Gateway rates at 1 Gbps

With client GSO, the gateway still receives 91,041.515 UDP datagrams per second. At an ideal `recvmmsg` batch of 256, the lower syscall bound is:

\[
\frac{91,041.515}{256}=355.631\ \text{recvmmsg calls/s}
\]

The gateway also performs 91,041.515 logical packet deliveries and approximately the same number of TUN writes per second.

With hypothetical N = 4 multi-frame messages:

- UDP and AEAD rate becomes 22,760.379 per second.
- TUN writes remain 91,041.515 per second.

Required gateway work depends on the selected mechanism:

- For Mechanism B, no protocol or receive-buffer change is required.
- For Mechanism A, `demuxReadBufferSize` must increase to an explicit authenticated message limit, all returned frames must be iterated, and oversized fragmented UDP must be accepted. I do not recommend that design.
- TUN multiqueue or multiple writers should be added only if gateway profiling shows the single TUN queue saturating. The packet rate alone does not prove saturation.
- Socket receive buffer sizing and `SO_RXQ_OVFL` should be observed during a 91,000 pps test.

Changing `demuxReadBufferSize` from 2,048 to 65,507 without a bounded allocation design is not surgical. A 256-entry fixed slab would consume:

\[
65,507 \times 256=16,769,792\ \text{bytes}
\]

That is approximately 16 MiB per batch slab and expands unauthenticated allocation exposure.

Vote OI-3: `DISAGREE: a UDP datagram larger than 2,048 bytes cannot be fully delivered through the current 2,048-byte recvmmsg iovec.`

**5. OI-4: Downlink freeze**

The acceptable Stage C scope is limited to:

- TUN reads that source client uplink traffic
- Uplink IPC framing and ownership
- `toEngineRing`
- Transmit-side frame packing
- Carrier send batching and GSO
- Gateway ingress processing for client-originated traffic

The following remain untouched:

- `RecvBatch`
- `outboundPump`
- `toHost`
- `fromEngine`
- Downlink plaintext ownership
- Downlink crypto workers and job pools
- Downlink allocation sizes
- Downlink measurement equations

Mechanism A should not be enabled through a shared carrier receive-buffer modification because that would alter a shared downlink allocation path. Mechanism B requires no receiver format change and therefore provides the cleanest treaty-compliant boundary.

Vote OI-4: `AGREE: transmit-only UDP_SEGMENT changes do not modify RecvBatch, outboundPump, toHost, fromEngine, or any downlink crypto worker.`

**6. Exact source-complete diff justified by the docket**

The docket does not include the carrier types, socket setup function, outbox representation, error handling contract, or current `sendmmsg` loop. An exact caller integration diff is therefore underdetermined. Inventing method names would not be an exact patch.

The following is a source-complete Linux helper for capability probing and transmission. It deliberately does not alter downlink behavior. The caller must pass concatenated complete Winn datagrams of equal length, except that the final datagram may be shorter.

```diff
diff --git a/winn_protocol_experimental/winn3/carrier/udp_gso_linux.go b/winn_protocol_experimental/winn3/carrier/udp_gso_linux.go
new file mode 100644
index 0000000..a74d89c
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/udp_gso_linux.go
@@ -0,0 +1,78 @@
+//go:build linux || android
+
+package carrier
+
+import (
+	"unsafe"
+
+	"golang.org/x/sys/unix"
+)
+
+const (
+	linuxSOLUDP         = 17
+	linuxUDPSegment     = 103
+	linuxUDPMaxSegments = 64
+	maxUDPSuperBuffer   = 65535
+)
+
+// ProbeUDPSegment checks whether fd accepts the Linux UDP_SEGMENT socket
+// option. It must be called before concurrent use of fd because the probe
+// temporarily changes the socket's default UDP segmentation size.
+func ProbeUDPSegment(fd int, segmentSize int) error {
+	if segmentSize < 1 || segmentSize > 65535 {
+		return unix.EINVAL
+	}
+	if err := unix.SetsockoptInt(
+		fd,
+		linuxSOLUDP,
+		linuxUDPSegment,
+		segmentSize,
+	); err != nil {
+		return err
+	}
+	return unix.SetsockoptInt(fd, linuxSOLUDP, linuxUDPSegment, 0)
+}
+
+// SendUDPSegments sends payload through a connected UDP socket. Payload must
+// contain complete UDP payloads concatenated at segmentSize boundaries. Every
+// segment except the last must have exactly segmentSize bytes.
+func SendUDPSegments(
+	fd int,
+	payload []byte,
+	segmentSize int,
+	flags int,
+) (int, error) {
+	if segmentSize < 1 || segmentSize > 65535 {
+		return 0, unix.EINVAL
+	}
+	if len(payload) <= segmentSize {
+		return 0, unix.EINVAL
+	}
+	if len(payload) > maxUDPSuperBuffer {
+		return 0, unix.EMSGSIZE
+	}
+
+	segments := (len(payload) + segmentSize - 1) / segmentSize
+	if segments < 2 || segments > linuxUDPMaxSegments {
+		return 0, unix.EMSGSIZE
+	}
+
+	oob := make([]byte, unix.CmsgSpace(2))
+	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
+	header.Level = linuxSOLUDP
+	header.Type = linuxUDPSegment
+	header.SetLen(unix.CmsgLen(2))
+
+	dataOffset := unix.CmsgLen(0)
+	*(*uint16)(unsafe.Pointer(&oob[dataOffset])) = uint16(segmentSize)
+
+	return unix.SendmsgN(fd, payload, oob, nil, flags)
+}
```

Activation requirements for the existing transmit loop are precise:

1. Group only already-encrypted datagrams with the same wire length.
2. Cap the first deployment at G = 16.
3. Keep the existing `sendmmsg` path as fallback.
4. On GSO failure, resend the original datagrams through `sendmmsg`.
5. Do not rebuild or re-encrypt them during fallback.
6. Record attempted segments, successful segments, fallback count, and errno.
7. Never pass a multi-frame ciphertext as a GSO super-buffer unless each segment is independently parseable and authenticated.

No gateway code diff is warranted for this GSO design because each received UDP datagram remains at or below the existing 1,402 byte wire-message limit. No downlink file requires modification.
