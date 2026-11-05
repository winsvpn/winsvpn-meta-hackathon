# Winthos Permanent Three-AI Presidential Debate Treaty (v4.0)
## Multi-Gbps Wire-Speed Across Winn v3, AWG, and XRay

**Codified under Winthos Presidential Council Binding Treaties (September 2026)**  
**Signatories**:
- **Podium 1**: Antigravity (Council Chair, Lead Systems Architect) -> AFFIRMATIVE
- **Podium 2**: GPT-5.6 Sol Pro (Principal AI Systems & Compiler Architect) -> AFFIRMATIVE
- **Podium 3**: Claude Opus 5 (Chief Auditor & Lead HPC Architect) -> AFFIRMATIVE

**Result: 3-0 Unanimous Binding Treaty Ratification.**

---

## 1. Preamble & Ground Truth Synthesis

Four stages of blind deliberation, adversarial cross-examination, and empirical verification establish the definitive technical facts governing VPN throughput across the Canada VPS gateway and mobile targets (Samsung Galaxy S26 Ultra):

1. **CPU Cryptographic Capacity**:
   Direct OpenSSL EVP benchmarks executed on the live Canada Haswell hardware (2.0 GHz, AVX2, AES-NI) prove:
   - ChaCha20-Poly1305 throughput: 1,218.9 MB/s (9.75 Gbps per core).
   - AES-256-GCM throughput: 1,611.7 MB/s (12.89 Gbps per core).
   - At 1 Gbps full-duplex wire rate (250 MB/s total crypto), ChaCha20-Poly1305 consumes 0.205 vCPU (20.5% of one core). AES-256-GCM consumes 0.155 vCPU (15.5% of one core). The delta is 0.05 core.
   - Pinned suite `winn3-x25519-mlkem768-chacha20poly1305-sha256` remains untouched. Cryptographic computation is not the bottleneck.

2. **The True Ingress Ceiling (`cover_demux.go:284-299`)**:
   One in four v3 datagrams (`pkt[0]&0x80 == 0 && pkt[0]&0x40 != 0`) executed `routeQUIC()`, acquiring `s.cidMu.Lock()` and performing a linear string scan across up to 4096 learned CIDs.
   At 85,150 pps (1 Gbps), 21,288 datagrams/sec entered this loop, requiring 87.2 million string comparisons per second. Within a 22.9-cycle budget on a 2.0 GHz core, this locked scan exhausted the single core, stalled `splitUDP.pump()`, overflowed the 8 MiB socket receive buffer (`udp_rcvbuf_errors = 96,200`), starved liveness probes, and tore down sessions above 600-700 Mbps.

3. **The Transmit Ceiling (`WAN_FQ_FLOW_LIMIT`)**:
   Measured `SndbufErrors = 263,060` on the Canada node was 2.7 times larger than receive errors. The default `fq_flow = 256` queue allowed only 1.5 ms of burst at 2 Gbps, causing repeated `ENOBUFS` retries and transmit latency spikes.

4. **Offload Deficit**:
   Zero occurrences of `UDP_SEGMENT` and `UDP_GRO` existed in the codebase. Traversal of 91,041 independent skbs per second on a single virtio ring pair consumed ~21,968 cycles per packet.

5. **Firewall & Client Factors**:
   - Suricata inline IPS on single NFQUEUE 0 dropped 125,188 packets on inbound TCP 443 with full userspace packet copies.
   - AWG was constrained by 1280 MTU / 1240 MSS on 1500-byte WAN paths.
   - Android TUN reader previously woke on single packets, which has been upgraded to an `O_NONBLOCK` burst drain with `Thread.MAX_PRIORITY` and `THREAD_PRIORITY_URGENT_AUDIO`.
   - S26 Ultra decoy calculator entered lockout due to `pin_attempt_state` monotonic rollback penalties, resolvable without destructive wipes.

---

## 2. Binding Execution Covenant (Tiered Rollout)

### Tier 1: Gateway Demultiplexer Serialization Dismantling

#### 1.1 Stateless Keyed CID Recognition (`cmd/winn3-gateway/cover_demux.go`)
Delete `s.cidMu`, `s.cids`, `s.cidOrder`, `maxLearnedCIDs`, and `learnCIDsFromLongHeader`. Replace with stateless, lock-free $O(1)$ arithmetic verification using self-authenticating server-issued CIDs:

```go
const (
	coverCIDLen      = 8
	coverCIDNonceLen = 4
	coverCIDTagLen   = 4
)

type coverCIDGen struct {
	block cipher.Block
}

func newCoverCIDGen() (*coverCIDGen, error) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &coverCIDGen{block: block}, nil
}

func (g *coverCIDGen) ConnectionIDLen() int { return coverCIDLen }

func (g *coverCIDGen) GenerateConnectionID() (quic.ConnectionID, error) {
	var raw [coverCIDLen]byte
	if _, err := rand.Read(raw[:coverCIDNonceLen]); err != nil {
		return quic.ConnectionID{}, err
	}
	var scratch [2][aes.BlockSize]byte
	tag := g.tag(raw[:coverCIDNonceLen], &scratch)
	copy(raw[coverCIDNonceLen:], tag[:coverCIDTagLen])
	return quic.ConnectionIDFromBytes(raw[:]), nil
}

func (g *coverCIDGen) tag(nonce []byte, scratch *[2][aes.BlockSize]byte) []byte {
	in, out := &scratch[0], &scratch[1]
	*in = [aes.BlockSize]byte{}
	copy(in[:], nonce)
	g.block.Encrypt(out[:], in[:])
	return out[:]
}

func (g *coverCIDGen) matches(pkt []byte, scratch *[2][aes.BlockSize]byte) bool {
	if len(pkt) < 1+coverCIDLen {
		return false
	}
	cid := pkt[1 : 1+coverCIDLen]
	want := g.tag(cid[:coverCIDNonceLen], scratch)
	return subtle.ConstantTimeCompare(
		cid[coverCIDNonceLen:], want[:coverCIDTagLen],
	) == 1
}

func (s *splitUDP) routeQUIC(pkt []byte, scratch *[2][aes.BlockSize]byte) bool {
	if isQUICLongHeader(pkt) {
		return true
	}
	if len(pkt) < 2 || pkt[0]&quicHeaderFormLong != 0 || pkt[0]&quicFixedBit == 0 {
		return false
	}
	return s.cidGen.matches(pkt, scratch)
}
```

#### 1.2 Delete Dead Allocations & Batch Channel Delivery
1. Delete line 217 in `cover_demux.go` (`na: net.UDPAddrFromAddrPort(msgs[i].Addr)`). Eliminate 5.45 MB/s of heap garbage. Construct `*net.UDPAddr` lazily only inside `ReadFrom()`.
2. Convert channel from single-element `chan demuxDatagram` to slice batch `chan []demuxDatagram`.
3. Replace mutex-protected `readDeadline` with `atomic.Int64` (storing Unix nanoseconds), eliminating 85,150 lock acquisitions/sec.

#### 1.3 Transmit Qdisc Flow Limit
Raise `WAN_FQ_FLOW_LIMIT` from 256 to 2048 packets on `ens3`:
```bash
tc qdisc change dev ens3 root fq flow_limit 2048 limit 20480
```

---

### Tier 2: Kernel Offload Pipeline (`UDP_SEGMENT` & `UDP_GRO`)

#### 2.1 Ancestral Control Buffer Plumbing
Plumb `rctl` cmsghdr buffers into `RawBatchConn.ReadBatchFrom` (`winn3/carrier/udp_batch_unix.go`):
```go
var groControlLen = unix.CmsgSpace(4)

// Set in per-slot setup:
c.rhs[i].hdr.control = &c.rctl[i][0]
c.rhs[i].hdr.controllen = uint64(groControlLen)
```

#### 2.2 Superframe Unpacking (`explode()`)
Parse `UDP_GRO` cmsg and explode superframes into 4096-byte pooled segment buffers prior to AEAD decryption. Raise pump iovec to 64 KiB for coalesced frames while keeping queue buffers bounded at 4096 bytes:
```go
func groSegmentSize(ctl []byte) int {
	msgs, err := unix.ParseSocketControlMessage(ctl)
	if err != nil {
		return 0
	}
	for i := range msgs {
		if msgs[i].Header.Level != 17 || msgs[i].Header.Type != 104 { // SOL_UDP, UDP_GRO
			continue
		}
		if len(msgs[i].Data) < 4 {
			continue
		}
		size := int(int32(binary.NativeEndian.Uint32(msgs[i].Data[:4])))
		if size <= 0 {
			return 0
		}
		return size
	}
	return 0
}
```

#### 2.3 Socket Options Activation
Enable `UDP_GRO` on listen socket:
```go
unix.SetsockoptInt(fd, 17, 104, 1) // SOL_UDP, UDP_GRO
```
Attach `UDP_SEGMENT` cmsg on transmit batches in `WriteBatchTo` for v3 frames.

---

### Tier 3: Network Stack & Security Posture Configuration

#### 3.1 Kernel Packet Steering (RPS Mask `0f`)
Configure core affinity on Canada node:
- CPU 4: IRQ 36 (`virtio0-input.0`) hardware interrupt & NAPI polling.
- CPU 5: IRQ 37 (`virtio0-output.0`) hardware interrupt & TX reclamation.
- CPUs 0-3: RPS protocol stack processing and gateway workers.

Commands:
```bash
IF=ens3
printf '10\n' > /proc/irq/36/smp_affinity
printf '20\n' > /proc/irq/37/smp_affinity
printf '0f\n' > /sys/class/net/$IF/queues/rx-0/rps_cpus
printf '16384\n' > /sys/class/net/$IF/queues/rx-0/rps_flow_cnt
sysctl -w net.core.rps_sock_flow_entries=65536
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.core.netdev_max_backlog=250000

# XPS is disabled on single TX queue:
printf '00\n' > /sys/class/net/$IF/queues/tx-0/xps_cpus
```

#### 3.2 Suricata NFQUEUE Bypass for XRay TCP 443
Accept inbound TCP 443 before the NFQUEUE inspection rule in `WINVPN-INPUT`:
```bash
iptables -I WINVPN-INPUT 1 -p tcp -m tcp --dport 443 -j ACCEPT
ip6tables -I WINVPN-INPUT 1 -p tcp -m tcp --dport 443 -j ACCEPT
```
Eliminates 125,188 packet drops and avoids userspace copying of encrypted TLS 1.3 traffic.

#### 3.3 Protocol Framing & Liveness Invariants
1. **Liveness Refresh**: Any authenticated frame (payload data or control) resets `lastRx` timestamp. Bulk upload traffic never times out due to queued keepalive probes.
2. **Buffer Drop Policy**: In-order TCP queues (`toEngine` and `toHost`) strictly enforce non-blocking tail-drop.
3. **AWG Configuration**: Inner MTU pinned at 1440, MSS clamp pinned at 1400.
4. **XRay Buffer**: Client `bufferSize` confirmed at 4096 (4 MB).

#### 3.4 S26 Ultra Decoy Calculator Lockout Recovery
Do not execute destructive `pm clear`. The lockout gate (`local_security.dart:445-447`) is bounded by 300 seconds.
Procedure:
1. Keep the S26 Ultra powered on without rebooting (preventing `rearmAfterMonotonicRollback`).
2. Allow the 300-second monotonic penalty timer to expire.
3. Enter PIN `142536=`.
4. Alternatively, surgically remove `pin_attempt_state` from secure storage via debug bridge, leaving client certificates, keys, and enrollment profiles intact.

---

## 3. Invalidation Thresholds & Guardrails

1. **Memory Ceiling**: Gateway process memory must not exceed `MemoryHigh = 120M` / `MemoryMax = 160M`. `GOMEMLIMIT = 96MiB` is strictly enforced.
2. **Zero Ingress Loss**: `UdpRcvbufErrors` must show zero delta during a sustained 1.5 Gbps wire test.
3. **Zero Egress Loss**: `SndbufErrors` must show zero delta under full duplex saturation.
4. **Fail-Closed Gate**: If any test binary yields an uncaught panic, rollback is triggered automatically.

---

## 4. Ratification Signatures

```
PODIUM 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

PODIUM 2: GPT-5.6 Sol Pro (Principal AI Systems & Compiler Architect, OpenAI)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

PODIUM 3: Claude Opus 5 (Chief Auditor & Lead HPC Architect, Anthropic)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED
```

---

## 5. Cryptographic Commitment
- Treaty Status: FINAL UNANIMOUS BINDING COVENANT
- Timestamp: 2026-09-17T23:05:00-04:00
- Protocol: Winthos Debate Protocol v4.0


SHA-256: 57d06b46a2b536c044cc2f4d96b977792236ac9bfcf6fb0fd497b3ec54d7bcb0
