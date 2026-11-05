# Stage 1 Submission: Podium 2 (GPT-5.6 Sol Pro)

# Independent technical determination

## 1. Verdict

**Single VPN at 1.5 Gbps is immediately credible. Single VPN at 1.85 to 1.92 Gbps payload is technically plausible. A reported 2.00 Gbps application payload is not guaranteed by a 2.00 Gbps physical service.**

The present download result needs these gains:

\[
G_{1.5}=\frac{1500}{1345.38}=1.115
\]

Only an 11.5 percent improvement is needed for 1.5 Gbps.

\[
G_{2.0}=\frac{2000}{1345.38}=1.4866
\]

A 48.7 percent improvement is needed for 2.0 Gbps.

For simultaneous 2.0 Gbps download and upload:

\[
G_{\text{full duplex}}=\frac{4000}{2469.8}=1.6196
\]

That requires a 62.0 percent increase in aggregate processing capacity.

**UDP GRO is the highest priority for handset download. UDP GSO is the highest priority for handset upload. Both features must also be deployed in the opposite endpoint because download transmit batching occurs on the server, not on the handset.**

**The 16 MB socket change is secondary.** At 2 Gbps:

\[
t_{8MiB}=\frac{8 \times 2^{20} \times 8}{2 \times 10^9}=33.55\text{ ms}
\]

\[
t_{16MiB}=67.11\text{ ms}
\]

An 8 MiB queue already absorbs approximately 33.6 ms of scheduling delay. With a 12 ms RTT, the bandwidth delay product is:

\[
BDP=\frac{2 \times 10^9 \times 0.012}{8}=3,000,000\text{ bytes}
\]

The existing 8 MiB allocation exceeds that BDP by 2.80 times. Increasing it will raise throughput only if kernel queue overflow or scheduling pauses longer than approximately 33 ms are observed.

**Double VPN at 500 Mbps is a reasonable engineering target. Double VPN at 1.5 Gbps cannot be certified from the supplied data because no isolated Hop 1, isolated Hop 2, or nested result was supplied.**

Its upper bound is:

\[
T_{\text{double}} \leq \min(T_{\text{hop1}},T_{\text{hop2}},T_{\text{crypto}},T_{\text{packet}})
\]

If both tunnel stages execute on one CPU pool and have per-byte costs \(c_1\) and \(c_2\):

\[
T_{\text{double}}=\frac{F}{c_1+c_2}
\]

If each stage independently reaches 2 Gbps only because it saturates the same core, two equal stages on that core yield approximately:

\[
T_{\text{double}}=\frac{2}{2}=1\text{ Gbps}
\]

Separating the two crypto stages onto different cores changes the bound from the sum of their costs to approximately the slower stage.

---

# 2. Wire-rate and packet-rate limits

At an inner MTU of 1373 bytes:

\[
PPS_{2G}=\frac{2 \times 10^9}{1373 \times 8}=182,083\text{ packets/s}
\]

The average interval is:

\[
\frac{1}{182083}=5.49\text{ microseconds}
\]

Your current 1,345.38 Mbps result corresponds to approximately:

\[
\frac{1.34538 \times 10^9}{1373 \times 8}=122,485\text{ packets/s}
\]

The simultaneous 2,469.80 Mbps result corresponds to approximately 224,855 full-sized inner packets per second. Smaller ACKs and control packets increase the actual packet rate.

This explains why batching produced such a large gain. At 2 Gbps, a per-packet syscall budget of only 5.49 microseconds exists before encryption, decryption, routing, checksum work, scheduling, and copying are counted.

With 1373-byte equal-sized encrypted UDP payloads, a conservative GSO batch can contain:

\[
\left\lfloor\frac{65507}{1373}\right\rfloor=47\text{ segments}
\]

The transmit syscall rate then falls from approximately 182,083 calls per second to:

\[
\frac{182083}{47}=3,874\text{ calls/s}
\]

The kernel still emits independent UDP datagrams. The saving is syscall, scheduler, socket-lock, and repeated stack-entry overhead.

## Physical line accounting

If 2.00 Gbps is the Ethernet line rate rather than IP service rate, application payload cannot equal 2.00 Gbps.

For a 1500-byte IPv4 TCP packet:

* TCP payload: 1460 bytes
* Ethernet frame plus preamble and inter-frame gap: approximately 1538 wire bytes

\[
\eta=\frac{1460}{1538}=0.9493
\]

\[
T_{\max}=2.0 \times 0.9493=1.899\text{ Gbps}
\]

A VLAN tag or tunnel encapsulation lowers that value slightly. Therefore, 1.85 to 1.90 Gbps application throughput can represent full utilization of a nominal 2 Gbps physical service.

If the provider instead shapes at 2 Gbps of IP packets, the corresponding TCP payload bound is approximately:

\[
2.0 \times \frac{1460}{1500}=1.947\text{ Gbps}
\]

Use physical interface counters to determine which definition applies.

---

# 3. Interpretation of the existing evidence

The following conclusions are directly supported by the supplied measurements:

1. **The original 425 Mbps ceiling was not a WAN ceiling.** The optimized engine reached 1,345.38 Mbps on the same handset and access path.

2. **The datapath supports at least 2.47 Gbps of aggregate bidirectional work.** The simultaneous result proves that much combined processing and transport capacity.

3. **The public Ookla result does not identify the engine ceiling.** Its 637 Mbps result is 47.4 percent of the isolated 1,345.38 Mbps result. Server selection, route, congestion control, and public Internet capacity changed with the test.

4. **Zero engine drops across 3.73 million packets proves the application queue survived that sample.** It does not prove that the UDP socket, network softirq backlog, NIC, remote endpoint, or TCP layer had no drops. Those require `SO_RXQ_OVFL`, `/proc/net/softnet_stat`, `nstat`, and retransmission counters.

---

# 4. Exact Go UDP GSO and GRO implementation

The repository was not supplied, so file paths and call-site symbol names cannot be matched to your tree. The following is a complete Linux and Android drop-in implementation.

## `udpoffload_linux.go`

```go
//go:build linux

package datapath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	udpSegment = 103
	udpGRO     = 104

	maxUDPPayload = 65507
	targetSockBuf = 16 << 20
)

type UDPBufferState struct {
	ReadBytes  int
	WriteBytes int
}

func ConfigureUDPOffload(c *net.UDPConn) (UDPBufferState, bool, error) {
	if err := c.SetReadBuffer(targetSockBuf); err != nil {
		return UDPBufferState{}, false, fmt.Errorf("set read buffer: %w", err)
	}
	if err := c.SetWriteBuffer(targetSockBuf); err != nil {
		return UDPBufferState{}, false, fmt.Errorf("set write buffer: %w", err)
	}

	var state UDPBufferState
	var groEnabled bool
	var socketErr error

	raw, err := c.SyscallConn()
	if err != nil {
		return state, false, err
	}

	if err := raw.Control(func(fd uintptr) {
		n := int(fd)

		state.ReadBytes, socketErr =
			unix.GetsockoptInt(n, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if socketErr != nil {
			return
		}

		state.WriteBytes, socketErr =
			unix.GetsockoptInt(n, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if socketErr != nil {
			return
		}

		if err := unix.SetsockoptInt(
			n,
			unix.SOL_SOCKET,
			unix.SO_RXQ_OVFL,
			1,
		); err != nil {
			socketErr = err
			return
		}

		if err := unix.SetsockoptInt(
			n,
			unix.SOL_UDP,
			udpGRO,
			1,
		); err == nil {
			groEnabled = true
		} else if !errors.Is(err, unix.ENOPROTOOPT) &&
			!errors.Is(err, unix.EINVAL) &&
			!errors.Is(err, unix.EOPNOTSUPP) {
			socketErr = err
		}
	}); err != nil {
		return state, false, err
	}

	if socketErr != nil {
		return state, false, socketErr
	}

	return state, groEnabled, nil
}

func makeGSOCmsg(segmentSize int) ([]byte, error) {
	if segmentSize <= 0 || segmentSize > 65535 {
		return nil, fmt.Errorf("invalid GSO segment size %d", segmentSize)
	}

	oob := make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))

	hdr.Level = int32(unix.SOL_UDP)
	hdr.Type = int32(udpSegment)
	hdr.SetLen(unix.CmsgLen(2))

	start := unix.CmsgLen(0)
	binary.NativeEndian.PutUint16(
		oob[start:start+2],
		uint16(segmentSize),
	)

	return oob, nil
}

// WriteGSO sends independently encrypted records as UDP segments.
// Every record except the last must have segmentSize bytes.
// payload must contain the records consecutively.
func WriteGSO(
	c *net.UDPConn,
	payload []byte,
	segmentSize int,
	dst *net.UDPAddr,
) error {
	if len(payload) <= segmentSize {
		if dst == nil {
			_, err := c.Write(payload)
			return err
		}
		_, err := c.WriteToUDP(payload, dst)
		return err
	}

	if len(payload) > maxUDPPayload {
		return fmt.Errorf(
			"GSO payload %d exceeds %d",
			len(payload),
			maxUDPPayload,
		)
	}

	segments := (len(payload) + segmentSize - 1) / segmentSize
	if segments > 64 {
		return fmt.Errorf("GSO segment count %d exceeds 64", segments)
	}

	oob, err := makeGSOCmsg(segmentSize)
	if err != nil {
		return err
	}

	n, _, err := c.WriteMsgUDP(payload, oob, dst)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return syscall.EIO
	}

	return nil
}

func IsGSOUnsupported(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL)
}

func WriteWithoutGSO(
	c *net.UDPConn,
	payload []byte,
	segmentSize int,
	dst *net.UDPAddr,
) error {
	for offset := 0; offset < len(payload); offset += segmentSize {
		end := offset + segmentSize
		if end > len(payload) {
			end = len(payload)
		}

		var err error
		if dst == nil {
			_, err = c.Write(payload[offset:end])
		} else {
			_, err = c.WriteToUDP(payload[offset:end], dst)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type GROResult struct {
	SocketDrops uint32
	Segments    int
}

// ReadGRO reads one UDP datagram or one GRO aggregate.
// consume must decrypt and authenticate each supplied record separately.
func ReadGRO(
	c *net.UDPConn,
	data []byte,
	oob []byte,
	consume func([]byte) error,
) (GROResult, error) {
	n, oobn, flags, _, err := c.ReadMsgUDP(data, oob)
	if err != nil {
		return GROResult{}, err
	}

	if flags&unix.MSG_TRUNC != 0 {
		return GROResult{}, fmt.Errorf("UDP payload truncated")
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return GROResult{}, fmt.Errorf("UDP control message truncated")
	}

	result := GROResult{}
	segmentSize := 0

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return result, err
	}

	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.SOL_UDP &&
			msg.Header.Type == udpGRO:
			if len(msg.Data) < 2 {
				return result, fmt.Errorf("short UDP_GRO control message")
			}
			segmentSize = int(binary.NativeEndian.Uint16(msg.Data[:2]))

		case msg.Header.Level == unix.SOL_SOCKET &&
			msg.Header.Type == unix.SO_RXQ_OVFL:
			if len(msg.Data) >= 4 {
				result.SocketDrops =
					binary.NativeEndian.Uint32(msg.Data[:4])
			}
		}
	}

	if segmentSize == 0 {
		result.Segments = 1
		return result, consume(data[:n])
	}

	if segmentSize > n {
		return result, fmt.Errorf(
			"GRO segment %d exceeds received bytes %d",
			segmentSize,
			n,
		)
	}

	for offset := 0; offset < n; offset += segmentSize {
		end := offset + segmentSize
		if end > n {
			end = n
		}
		if err := consume(data[offset:end]); err != nil {
			return result, err
		}
		result.Segments++
	}

	return result, nil
}
```

## Required call-site structure

```go
state, groEnabled, err := ConfigureUDPOffload(udpConn)
if err != nil {
	return err
}

logger.Printf(
	"UDP buffers read=%d write=%d gro=%t",
	state.ReadBytes,
	state.WriteBytes,
	groEnabled,
)

rxData := make([]byte, 65535)
rxOOB := make([]byte, 256)

for {
	result, err := ReadGRO(
		udpConn,
		rxData,
		rxOOB,
		func(record []byte) error {
			return decryptAndRouteOneRecord(record)
		},
	)
	if err != nil {
		return err
	}

	metrics.UDPSocketDrops.Store(uint64(result.SocketDrops))
	metrics.GROSegments.Add(uint64(result.Segments))
}
```

Outbound batching:

```go
err := WriteGSO(
	udpConn,
	encryptedBatch,
	encryptedRecordSize,
	remoteAddr,
)
if err != nil && IsGSOUnsupported(err) {
	metrics.GSOFallbacks.Add(1)
	err = WriteWithoutGSO(
		udpConn,
		encryptedBatch,
		encryptedRecordSize,
		remoteAddr,
	)
}
if err != nil {
	return err
}
```

## Encryption ordering requirement

Do not encrypt a 64 KB aggregate as one AEAD record and then apply `UDP_SEGMENT`.

Correct order:

1. Allocate one GSO slab.
2. Encrypt packet 1 with nonce and authentication tag 1.
3. Encrypt packet 2 with nonce and authentication tag 2.
4. Continue for equal-sized records.
5. Concatenate those complete records.
6. Submit them using `UDP_SEGMENT`.

Receive order:

1. Read the GRO aggregate.
2. Split it using the `UDP_GRO` segment size.
3. Authenticate and decrypt each segment independently.
4. Apply replay checks to each independent sequence number.

GSO only creates UDP boundaries. It cannot create missing AEAD nonces or authentication tags.

Group records by encrypted UDP payload length. Full-sized data packets should form one bucket. ACKs and short control packets should use ordinary sends or separate same-length buckets.

---

# 5. Lock-free ring and direct TUN ownership

A userspace ring cannot create complete kernel zero-copy operation. TUN reads copy a packet from the kernel, and UDP sends copy or map data into the networking stack according to the active kernel path.

The useful target is narrower: no allocation and no additional copy between the TUN reader, crypto worker, and UDP batch builder.

## Exact SPSC ring

```go
package datapath

import (
	"errors"
	"sync/atomic"
)

const (
	ringSlots = 1024
	ringMask  = ringSlots - 1
	slotBytes = 2048
)

var ErrRingFull = errors.New("packet ring full")

type packetSlot struct {
	N uint16
	B [slotBytes]byte
}

type packetRing struct {
	head atomic.Uint32
	_pad0 [60]byte

	tail atomic.Uint32
	_pad1 [60]byte

	slots [ringSlots]packetSlot
}

func (r *packetRing) BeginProduce() (*packetSlot, uint32, error) {
	head := r.head.Load()
	next := (head + 1) & ringMask

	if next == r.tail.Load() {
		return nil, 0, ErrRingFull
	}

	return &r.slots[head], next, nil
}

func (r *packetRing) CommitProduce(next uint32, n int) {
	index := (next - 1) & ringMask
	r.slots[index].N = uint16(n)
	r.head.Store(next)
}

func (r *packetRing) BeginConsume() (*packetSlot, uint32, bool) {
	tail := r.tail.Load()
	if tail == r.head.Load() {
		return nil, 0, false
	}

	next := (tail + 1) & ringMask
	return &r.slots[tail], next, true
}

func (r *packetRing) CommitConsume(next uint32) {
	r.tail.Store(next)
}
```

The TUN reader reads directly into the reserved slot:

```go
slot, next, err := outboundRing.BeginProduce()
if err != nil {
	metrics.TUNBackpressure.Add(1)
	return err
}

n, err := readTUNPacket(tunFD, slot.B[:])
if err != nil {
	return err
}

outboundRing.CommitProduce(next, n)
```

At 1373 bytes, 1024 slots hold:

\[
\frac{1024 \times 1373 \times 8}{2 \times 10^9}=5.62\text{ ms}
\]

That is enough to absorb a short scheduling interruption without allocating per packet. If the ring fills, backpressure should be measured rather than silently dropping.

## Correct TUN write behavior

Do not use one `writev` call to write several independent packets to a normal TUN descriptor. One TUN write represents one packet. Multiple iovecs in one `writev` can be interpreted as one combined packet.

Use one write per packet:

```go
package datapath

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func writeTUNPacket(fd int, packet []byte) error {
	for {
		n, err := unix.Write(fd, packet)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			pollFD := []unix.PollFd{
				{
					Fd:     int32(fd),
					Events: unix.POLLOUT,
				},
			}
			if _, pollErr := unix.Poll(pollFD, -1); pollErr != nil {
				return pollErr
			}
			continue
		}
		if err != nil {
			return err
		}
		if n != len(packet) {
			return fmt.Errorf(
				"short TUN write: %d of %d",
				n,
				len(packet),
			)
		}
		return nil
	}
}
```

The current 60 microsecond spin covers approximately:

\[
\frac{60}{5.49}=10.9
\]

packet intervals at 2 Gbps. It can consume an entire CPU while approximately eleven additional packets arrive. Test these two modes separately:

1. Immediate `poll` on `EAGAIN`.
2. A bounded 5 microsecond spin followed by `poll`.

Retain 60 microseconds only if an A/B test proves higher throughput without starving crypto or softirq work.

---

# 6. Kotlin Android host modification

The cleanest boundary is to transfer ownership of the TUN descriptor to Go. Remove the Kotlin 1 MB packet accumulator from the steady-state datapath.

```kotlin
private val engineExecutor =
    java.util.concurrent.Executors.newSingleThreadExecutor()

@Volatile
private var running = false

fun startTunnel() {
    check(!running)

    val tunPfd = Builder()
        .setSession("Winthos VPN")
        .setMtu(1373)
        .addAddress("10.10.0.14", 24)
        .addRoute("0.0.0.0", 0)
        .establish()
        ?: error("VpnService establish returned null")

    val tunFd = tunPfd.detachFd()

    val transportFd = NativeEngine.prepareTransport(
        "192.168.4.36",
        9111
    )

    if (!protect(transportFd)) {
        android.system.Os.close(tunFd)
        NativeEngine.closeTransport()
        error("VpnService protect failed")
    }

    running = true

    engineExecutor.execute {
        try {
            NativeEngine.runWithTunFd(tunFd)
        } finally {
            try {
                android.system.Os.close(tunFd)
            } catch (_: Throwable) {
            }

            NativeEngine.closeTransport()
            running = false
        }
    }
}

fun stopTunnel() {
    NativeEngine.requestStop()
}
```

Required JNI or gomobile contract:

```kotlin
object NativeEngine {
    external fun prepareTransport(host: String, port: Int): Int
    external fun runWithTunFd(tunFd: Int)
    external fun requestStop()
    external fun closeTransport()
}
```

`prepareTransport` must retain the Go `UDPConn` while returning its file descriptor for `VpnService.protect(int)`. The UDP socket must not send traffic before protection succeeds.

The ownership model becomes:

* Kotlin owns the `ParcelFileDescriptor` until `detachFd`.
* Go owns the UDP connection.
* Kotlin protects the UDP socket descriptor.
* Go owns steady-state TUN reads and writes.
* The executor cleanup closes the detached TUN descriptor exactly once.

This removes JNI transitions, Kotlin byte-array allocation, accumulator copying, and Kotlin scheduling from the per-packet path.

---

# 7. MTU determination for double VPN

First determine whether the design is serial or truly nested.

## Serial termination

If Hop 1 terminates on aicore, exposes the original inner IP packet, and Hop 2 independently encrypts that packet, the encapsulations are not simultaneously present.

The effective inner MTU is:

\[
M=\min(P-O_1,P-O_2)
\]

For a 1500-byte physical MTU and a maximum single-hop overhead of 80 bytes:

\[
M=1500-80=1420
\]

An inner MTU of 1373 is safe by 47 bytes.

## True nesting

If the entire Hop 1 tunnel datagram is carried inside Hop 2:

\[
M=P-O_1-O_2
\]

A WireGuard-style UDP tunnel typically consumes:

* IPv4 outer IP: 20 bytes
* UDP: 8 bytes
* Tunnel data header and authentication: 32 bytes
* Total IPv4 overhead: 60 bytes
* Total IPv6 overhead: 80 bytes

Two IPv4 layers produce:

\[
M=1500-60-60=1380
\]

The 1373 setting is safe by 7 bytes.

Two IPv6 layers produce:

\[
M=1500-80-80=1340
\]

The 1373 setting is too large by 33 bytes.

A quoted 32-byte tunnel header is not total wire overhead if IP and UDP headers were excluded.

Under the stated additional overhead of 32 to 80 bytes, if the complete packet entering Hop 2 is 1373 bytes:

\[
1373+80=1453
\]

That remains below 1500. Packet capture must confirm that 1373 is the complete Hop 2 input packet rather than only its plaintext payload.

## Verification

On aicore:

```bash
tcpdump -ni any -vv -s 0 'udp port 9111'
```

Look for:

* Outer IP total length
* `frag` indications
* IPv4 MF flag
* Nonzero fragment offsets
* IPv6 fragment extension headers

For a 1373-byte IPv4 inner packet:

```bash
ping -M do -s 1345 10.10.0.14
```

The 1345-byte ICMP payload plus 20-byte IPv4 and 8-byte ICMP headers equals 1373 bytes.

For IPv6:

```bash
ping -6 -M do -s 1325 10.10.0.14
```

The 1325-byte payload plus 40-byte IPv6 and 8-byte ICMPv6 headers also equals 1373 bytes.

---

# 8. Exact aicore sysctls

Create `/etc/sysctl.d/90-win-vpn.conf`:

```conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304

net.core.netdev_max_backlog = 16384
net.core.rps_sock_flow_entries = 32768

net.ipv4.udp_rmem_min = 262144
net.ipv4.udp_wmem_min = 262144

net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_mtu_probing = 1

net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
```

Apply and verify:

```bash
sudo sysctl --system

sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
sysctl net.core.rmem_max
sysctl net.core.wmem_max
sysctl net.core.netdev_max_backlog
```

Linux commonly reports a doubled `SO_RCVBUF` or `SO_SNDBUF` value because internal accounting includes protocol overhead. Log the actual `getsockopt` values rather than assuming the request was honored.

Do not change `udp_mem` without using the host page size and installed RAM. Its values are pages, not bytes.

---

# 9. Interface MTU and MSS clamping

Assume:

```bash
H1=winn3gw0
H2=wg-ca1
INNER_NET=10.10.0.0/24
MTU=1373
```

Set the routed tunnel MTU:

```bash
sudo ip link set dev "$H1" mtu "$MTU"
sudo ip link set dev "$H2" mtu "$MTU"
```

The TCP MSS values are:

\[
MSS_{IPv4}=1373-20-20=1333
\]

\[
MSS_{IPv6}=1373-40-20=1313
\]

## iptables rules

Use PMTU-based clamping in both directions:

```bash
sudo iptables -t mangle -A FORWARD \
  -i "$H1" -o "$H2" \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

sudo iptables -t mangle -A FORWARD \
  -i "$H2" -o "$H1" \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
```

Permit forwarding:

```bash
sudo iptables -A FORWARD \
  -i "$H1" -o "$H2" \
  -s "$INNER_NET" \
  -j ACCEPT

sudo iptables -A FORWARD \
  -i "$H2" -o "$H1" \
  -d "$INNER_NET" \
  -m conntrack --ctstate ESTABLISHED,RELATED \
  -j ACCEPT
```

Permit IPv4 PMTU errors:

```bash
sudo iptables -A FORWARD \
  -p icmp --icmp-type fragmentation-needed \
  -j ACCEPT
```

For IPv6:

```bash
sudo ip6tables -t mangle -A FORWARD \
  -i "$H1" -o "$H2" \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

sudo ip6tables -t mangle -A FORWARD \
  -i "$H2" -o "$H1" \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

sudo ip6tables -A FORWARD \
  -p ipv6-icmp --icmpv6-type packet-too-big \
  -j ACCEPT
```

Use NAT only if the Hop 2 gateway does not have a route back to `10.10.0.0/24`:

```bash
sudo iptables -t nat -A POSTROUTING \
  -s "$INNER_NET" \
  -o "$H2" \
  -j MASQUERADE
```

Routing is preferable to NAT when the remote gateway can install:

```bash
ip route add 10.10.0.0/24 via <aicore-hop2-address>
```

## nftables alternative

Do not install these rules in parallel with the equivalent iptables rules.

```bash
sudo nft add table inet vpn_mangle

sudo nft 'add chain inet vpn_mangle forward {
  type filter hook forward priority mangle;
  policy accept;
}'
```

Fixed MTU 1373 clamps:

```bash
sudo nft add rule inet vpn_mangle forward \
  iifname "winn3gw0" oifname "wg-ca1" \
  meta nfproto ipv4 \
  tcp flags \& \(syn\|rst\) == syn \
  tcp option maxseg size \> 1333 \
  tcp option maxseg size set 1333

sudo nft add rule inet vpn_mangle forward \
  iifname "wg-ca1" oifname "winn3gw0" \
  meta nfproto ipv4 \
  tcp flags \& \(syn\|rst\) == syn \
  tcp option maxseg size \> 1333 \
  tcp option maxseg size set 1333

sudo nft add rule inet vpn_mangle forward \
  iifname "winn3gw0" oifname "wg-ca1" \
  meta nfproto ipv6 \
  tcp flags \& \(syn\|rst\) == syn \
  tcp option maxseg size \> 1313 \
  tcp option maxseg size set 1313

sudo nft add rule inet vpn_mangle forward \
  iifname "wg-ca1" oifname "winn3gw0" \
  meta nfproto ipv6 \
  tcp flags \& \(syn\|rst\) == syn \
  tcp option maxseg size \> 1313 \
  tcp option maxseg size set 1313
```

---

# 10. Kernel forwarding, FQ, and queue configuration

Strict zero-copy cannot be promised through two encrypted tunnels. The achievable gateway design is:

* No userspace router between tunnel interfaces.
* Kernel IP forwarding for the exposed inner packet.
* Tunnel encryption and decryption remain in their respective kernel or userspace engines.
* No extra proxy, socket relay, or packet serialization layer.

Configure FQ on the Hop 2 tunnel and physical egress:

```bash
H2=wg-ca1
PHY=enp3s0

sudo ip link set dev "$H2" txqueuelen 2048
sudo ip link set dev "$PHY" txqueuelen 2048

sudo tc qdisc replace dev "$H2" root fq \
  limit 8192 \
  flow_limit 2048 \
  quantum 1514 \
  initial_quantum 15140

sudo tc qdisc replace dev "$PHY" root fq \
  limit 8192 \
  flow_limit 2048 \
  quantum 1514 \
  initial_quantum 15140
```

At 1.5 Gbps, a 2048-packet queue of 1373-byte packets represents an upper bound of:

\[
\frac{2048 \times 1373 \times 8}{1.5 \times 10^9}=15.0\text{ ms}
\]

FQ should be retained for flow isolation and pacing, not treated as a source of additional CPU throughput. Raise queue limits only if `tc -s qdisc` reports drops during a controlled test.

Inspect:

```bash
tc -s qdisc show dev "$H2"
tc -s qdisc show dev "$PHY"
ip -s link show dev "$H2"
ip -s link show dev "$PHY"
```

---

# 11. RPS and XPS steering

Example for systems with CPUs numbered below 32:

```bash
#!/usr/bin/env bash
set -euo pipefail

CPUS=(2 3 4 5)
DEVS=(enp3s0 wg-ca1 winn3gw0)

for dev in "${DEVS[@]}"; do
  i=0

  for q in /sys/class/net/"$dev"/queues/rx-*; do
    [ -e "$q/rps_cpus" ] || continue

    cpu="${CPUS[$((i % ${#CPUS[@]}))]}"
    mask=$((1 << cpu))

    printf '%x\n' "$mask" |
      sudo tee "$q/rps_cpus" >/dev/null

    if [ -e "$q/rps_flow_cnt" ]; then
      echo 4096 |
        sudo tee "$q/rps_flow_cnt" >/dev/null
    fi

    i=$((i + 1))
  done

  i=0

  for q in /sys/class/net/"$dev"/queues/tx-*; do
    [ -e "$q/xps_cpus" ] || continue

    cpu="${CPUS[$((i % ${#CPUS[@]}))]}"
    mask=$((1 << cpu))

    printf '%x\n' "$mask" |
      sudo tee "$q/xps_cpus" >/dev/null

    i=$((i + 1))
  done
done
```

A single outer UDP five-tuple normally hashes as one flow. RSS or RPS therefore tends to keep that outer tunnel flow on one CPU even when sixteen inner TCP streams exist. Those streams are hidden by encryption.

If one softirq CPU reaches 100 percent while other CPUs remain idle, the next scaling step is not a larger queue. It is one of:

1. UDP GRO large enough to reduce per-packet softirq work.
2. Kernel tunnel processing that distributes crypto jobs across CPUs.
3. Multiple authenticated outer transport lanes using distinct UDP source ports.
4. A worker pool with sequence assignment and an ordered completion stage.

A four-lane design reduces the ideal per-lane packet rate at 2 Gbps from 182,083 to:

\[
\frac{182083}{4}=45,521\text{ packets/s}
\]

It changes NAT behavior and replay-window design, so it should follow the GRO and GSO experiment rather than precede it.

---

# 12. Double VPN CPU budget

At 1.5 Gbps with 1373-byte packets:

\[
PPS=\frac{1.5 \times 10^9}{1373 \times 8}=136,562
\]

At 500 Mbps:

\[
PPS=\frac{0.5 \times 10^9}{1373 \times 8}=45,521
\]

For one 3 GHz core at 1.5 Gbps:

\[
\frac{3 \times 10^9}{136562}=21,968
\]

Only about 21,968 cycles are available per forwarded packet.

The equivalent per-byte budget is:

\[
\frac{3 \times 10^9}{1.5 \times 10^9 / 8}=16\text{ cycles/byte}
\]

That 16 cycles per byte must include Hop 1 decryption, Hop 2 encryption, packet validation, route lookup, queue handling, and memory movement if one core performs all work.

For simultaneous 1.5 Gbps in each direction, total byte processing doubles:

\[
\frac{3 \times 10^9}{3.0 \times 10^9 / 8}=8\text{ cycles/byte}
\]

One 3 GHz core is therefore unlikely to provide enough budget unless hardware crypto and large packet batching reduce the non-crypto cost substantially. Separate cores for receive, Hop 1 crypto, Hop 2 crypto, and transmit should be tested.

---

# 13. Required validation sequence

Change one variable per test. Run at least five 60-second samples and report median plus minimum.

## Phase A. Establish the real ceilings

Test:

1. No VPN.
2. Hop 1 only.
3. Hop 2 only.
4. Double VPN.
5. Each case download only.
6. Each case upload only.
7. Each case simultaneous bidirectional.

The double VPN result cannot exceed the lower isolated hop result.

## Phase B. Instrument before changing buffers

On aicore:

```bash
nstat -az | egrep \
  'UdpInErrors|UdpRcvbufErrors|UdpSndbufErrors|IpReasmFails|IpFragCreates'

cat /proc/net/softnet_stat

ss -u -a -n -i -m

tc -s qdisc show dev wg-ca1
tc -s qdisc show dev enp3s0
```

During a run:

```bash
sudo perf stat -p <engine-pid> \
  -e cycles,instructions,context-switches,cpu-migrations,cache-misses \
  sleep 60
```

Check thread saturation:

```bash
pidstat -t -p <engine-pid> 1 60
```

## Phase C. GSO and GRO matrix

Run these separately:

1. Neither GSO nor GRO.
2. GSO only.
3. GRO only.
4. GSO and GRO.
5. GSO and GRO with 8 MiB buffers.
6. GSO and GRO with 16 MiB buffers.

Record:

* GSO batch size distribution
* GSO fallback count
* GRO aggregate segment count
* `SO_RXQ_OVFL`
* UDP receive buffer errors
* CPU cycles per byte
* TUN `EAGAIN` count
* Ring full count
* TCP retransmissions

## Acceptance thresholds

For a nominal 2 Gbps physical service:

* Single VPN download median: at least 1.85 Gbps
* Single VPN upload median: at least 1.85 Gbps
* No kernel UDP queue drops
* No fragmentation
* No engine packet drops
* Stable throughput across 60 seconds
* CPU headroom on at least one core

For double VPN:

* First gate: 500 Mbps
* Second gate: 1.0 Gbps
* Final gate: 1.5 Gbps
* Each isolated hop must exceed the requested double VPN result
* Hop 1 and Hop 2 crypto should not saturate the same core
* `IpFragCreates` and `IpReasmFails` must remain unchanged

# Final priority order

1. Transfer the TUN descriptor directly to Go.
2. Add UDP GRO on every receiving tunnel endpoint.
3. Add UDP GSO on every transmitting tunnel endpoint.
4. Encrypt each GSO segment independently.
5. Measure kernel socket drops before increasing buffers.
6. Keep MTU 1373 only after proving the exact nesting model.
7. Apply bidirectional MSS clamping.
8. Use kernel forwarding on aicore, not a userspace relay.
9. Separate Hop 1 and Hop 2 crypto execution across CPU cores.
10. Add multiple outer UDP lanes only if one outer-flow CPU remains the measured ceiling.

The data already proves that the engine is capable of multi-gigabit aggregate work. The remaining 1.49 times single-direction gain depends primarily on reducing packet-rate cost, not on adding larger queues. UDP GRO, UDP GSO, direct TUN ownership, and measured CPU separation are the shortest path to that gain.
