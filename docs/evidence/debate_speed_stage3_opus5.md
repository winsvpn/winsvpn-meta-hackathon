Repo re-verification complete. Every Stage 2 citation holds, and I found two things in the carrier that settle the GRO dispute. Live web search was denied again, so this rests on repo evidence and arithmetic.

---

# Podium 3: Claude Opus 5. Stage 3 Synthesis and Position Lock

**Verification basis.** Every claim below is re-verified against the shipping tree at `/Users/owner/xprize/winsvpnv3` this stage, cited by `file:line`. Paths are relative to `winn_protocol_experimental/` unless prefixed. WebSearch was denied in this session, so the two items I flagged as needing external confirmation in Stage 2 (virtio GRO behavior on kernel 6.8, Samsung cpuset layout) stay flagged. I resolved neither by guessing.

---

## Part I: Absorbed Points

### I.1 Podium 2 was right that my GRO patch was broken. It is worse than Podium 2 knew.

Podium 2 §2.3 charged that I proposed `UDP_GRO` without the receive-side split, and that passing a 22,432-byte coalesced buffer to a Winn frame decoder produces an authentication failure. Accepted without reservation. I went to find the plumbing and found two hard blockers, both of which strengthen the charge:

**Blocker one: there is no control buffer anywhere on the receive path.** `winn3/carrier/udp_batch_unix.go:743-744` sets, per message slot:

```go
c.rhs[i].hdr.control = nil
c.rhs[i].hdr.controllen = 0
```

Identical at `ReadBatch` (lines 239-240) and at `WriteBatchTo` (lines 383-384). The `SOL_UDP`/`UDP_GRO` ancillary message carrying `gso_size` has nowhere to land. Reading it is not a matter of adding a parse step. The msghdr has to be re-plumbed first.

**Blocker two, and this one is a loss amplifier.** `ReadBatchFrom` treats `MSG_TRUNC` as a fatal per-slot error and discards the slot (`udp_batch_unix.go:761-763`):

```go
if c.rhs[i].hdr.flags&int32(unix.MSG_TRUNC) != 0 {
    msgs[i].Err = ErrMessageTooLarge
    continue
}
```

The pump's iovec is `demuxDatagramMax = 4096` (`cover_demux.go:63`). Set `UDP_GRO` on that socket today and the kernel coalesces up to 64 KiB into a 4096-byte iovec, sets `MSG_TRUNC`, and the gateway **throws away the whole superframe** and logs it as oversize. One discarded slot is up to 46 lost datagrams. Enabling GRO on the tree as it stands would not underperform. It would shred the downlink.

So Podium 2's "do not enable GRO until the receiver splits" is promoted from caution to hard precondition, and it gains a second precondition neither of us stated: raise the receive iovec to 64 KiB and stop conflating `MSG_TRUNC` with oversize, *before* `UDP_GRO` is ever set.

**And the transmit side cannot take the shortcut.** `setsockopt(SOL_UDP, UDP_SEGMENT, size)` would enable GSO socket-wide without touching the control field. That shortcut is unavailable here, because this socket is shared between v3 and QUIC cover by construction (`cover_demux.go:72-89`, `splitUDP` is "one real UDP socket presented as two PacketConns"). A socket-wide segment size would apply to quic-go's writes too. GSO here therefore requires the per-message `UDP_SEGMENT` cmsg, which requires the same plumbing. Both offloads collapse onto one prerequisite I did not previously name: **control-message support in `RawBatchConn`.** That is the real first step, not the `setsockopt`.

### I.2 Podium 2 was right that length-based control priority is remotely abusable.

My Stage 1 proposed classifying a datagram into a priority control lane when `msgs[i].N <= demuxControlPlaneMaxBytes`. That test runs before AEAD verification. Any sender reaching UDP 9111 can emit short datagrams, so a strict-priority reader would spend its reserved capacity on off-path traffic. The objection is correct and I withdraw the mechanism entirely.

I adopt Podium 2's replacement, which is both safer and simpler: **any authenticated frame refreshes liveness.** A session carrying authenticated bulk data must not die because a dedicated heartbeat queued behind that data. This removes the need for a privileged pre-authentication classifier rather than trying to harden one.

### I.3 Podium 2 was right that my CID copy-on-write patch preserved the attack. I withdraw my own remediation.

Podium 2 §2.8: an `atomic.Pointer` snapshot rebuilt per newly learned CID converts a locked read scan into repeated allocation and copy, and since learning is still pre-authentication, an off-path sender forces a fresh 4096-entry rebuild per novel CID. That is a worse denial-of-service primitive than the scan it replaces. Conceded.

Podium 2's prescription was to stop unauthenticated learning, or split the ports. I accept the principle and offer a construction that satisfies it without splitting anything. **Make connection ID recognition stateless.**

The listener's QUIC stack is `github.com/quic-go/quic-go v0.60.0` (`go.mod:9`), which exposes a connection ID generator on the transport. Every short header this gateway must recognize carries a CID the gateway itself issued. So issue CIDs that are self-authenticating and recognize them arithmetically. No table, no lock, no learning, no growth, and no pre-authentication write path of any kind.

```go
// coverCIDGen issues every connection ID this listener will ever have to
// recognize, so recognition needs no table. The tag is a keyed permutation of
// the nonce, which turns "is this short header ours" into a constant-time
// arithmetic question instead of a locked scan over as many as 4096 learned
// strings.
//
// AES, not HMAC-SHA256, and the reason is the cycle budget. The classifier runs
// on one in four v3 datagrams and its whole per-comparison budget on this
// 2.0 GHz Haswell is 22.9 cycles. One AES block with AES-NI fits. Two SHA-256
// compression blocks do not.
const (
	coverCIDLen      = 8
	coverCIDNonceLen = 4
	coverCIDTagLen   = 4
)

type coverCIDGen struct{ block cipher.Block }

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

// tag writes through caller-owned scratch. cipher.Block is an interface, so
// passing fresh arrays to Encrypt escapes them to the heap: two 16-byte
// allocations per classified datagram, which is the exact per-datagram garbage
// this whole change exists to delete.
func (g *coverCIDGen) tag(nonce []byte, scratch *[2][aes.BlockSize]byte) []byte {
	in, out := &scratch[0], &scratch[1]
	*in = [aes.BlockSize]byte{}
	copy(in[:], nonce)
	g.block.Encrypt(out[:], in[:])
	return out[:]
}

// matches reports whether pkt is a short header carrying a CID this gateway
// issued. No lock, no map, no allocation.
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
```

`routeQUIC` becomes O(1) and lock-free:

```go
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

`learnCIDsFromLongHeader`, `s.cids`, `s.cidOrder`, `s.cidMu`, `maxLearnedCIDs`, and the `learnCID` flag on `demuxSide` all get deleted (`cover_demux.go:86-88, 91-96, 102, 301-328, 377-379, 384-388, 414-416`).

**It also improves the classifier against its own stated budget.** The file sets its false-positive tolerance at `cover_demux.go:32-35`: three known QUIC versions matched against a high-entropy 32-bit field, so `3/2^32`, about `2^-30.4`. The stateless router's false-positive rate on a random v3 datagram is the two first-byte bits times a 32-bit tag:

$$P = \tfrac{1}{2} \times \tfrac{1}{2} \times 2^{-32} = 2^{-34}$$

Roughly 23 times tighter than the budget the file already accepts. Client-chosen DCIDs in Initial and Handshake packets stay long-header and keep using `isQUICLongHeader`, unchanged. Post-handshake short headers all carry server-issued CIDs. Coverage is complete.

### I.4 Podium 2 was right about my cipher arithmetic, by a factor of two.

My Stage 1 claimed a gateway sealing and opening at 2 Gbps aggregate spends 0.10 additional cores by choosing ChaCha20 over AES-GCM. Wrong.

$$\frac{125}{1218.911} - \frac{125}{1611.681} = 0.10256 - 0.07756 = 0.02500 \text{ core per Gbps}$$

At 2 Gbps aggregate that is **0.0500 core**, and 0.10 core requires 4 Gbps aggregate. My Stage 2 §12 figures (0.2051 and 0.1551, delta 0.0500) were correct and supersede the Stage 1 number. Strategic conclusion unchanged: cipher choice is not the constraint, and a 0.05-core saving does not buy an unpinned suite.

### I.5 Podium 2 was right that "red herring" overstated my case on the virtio queue.

I wrote that the single queue is a red herring. Podium 2 §2.5 answered that the node has exactly one receive ring and one transmit ring, that offloads reduce per-datagram guest work without creating a second ring, and that the correct statement is narrower. Accepted.

Precise retraction: the queue count is not the **binding** constraint at the observed 600 to 900 Mbps, which is what my evidence supports. It is not irrelevant. It becomes binding only after per-datagram guest cost falls, and even then only above the 1,742.7 Mbps that the same ring pair already carried on raw WAN.

### I.6 Podium 2 was right that my liveness causation was declared rather than proved. Partially, and with one correction.

Podium 2 §2.6: an 85.6 ms queue cannot explain a multi-second probe deadline without additional stalls, and the teardown reason, probe deadline, channel occupancy, and GC pause were never instrumented. Correct on the arithmetic gap, and I adopt the full instrumentation field list unchanged.

The correction is that the chain itself is not hypothetical. It is recorded in the tree, measured today, at `cover_demux.go:152-159`:

> MEASURED on the Canada node, 2026-09-17, during a sustained uplink run against the shipping gateway: `/proc/net/snmp` went from RcvbufErrors 0 to RcvbufErrors 82,318 and InErrors 82,318, and the session then failed its liveness probes and tore down. The 8 MiB receive buffer was not too small; the reader could not empty it.

Pump stall, then receive buffer overflow, then liveness failure, then teardown. Observed, not inferred. What remains genuinely open is **attribution after `pumpBatch` landed**, because that comment names the pre-batch scalar `recvfrom` loop as the cause and that loop is now the fallback path (`cover_demux.go:160-166, 237-282`). The comment's measurement dates are 2026-09-17, which is today. So the deliberation's 852 to 923 Mbps figures may predate the batch pump. That ordering has to be established before any profile is interpreted, and it is a question no podium asked.

### I.7 Absorbed from Podium 1

- **`SOL_UDP = 17`, `UDP_SEGMENT = 103`, `UDP_GRO = 104`,** verified by Podium 1 against live Linux 6.8 headers on Ubuntu 24.04. I could not run that check here, so I take Podium 1's verification and cite it as the source. Prefer `unix.SOL_UDP`, `unix.UDP_SEGMENT`, `unix.UDP_GRO` if the vendored `golang.org/x/sys v0.47.0` (`go.mod:13`) exports them; fall back to named local constants if it does not.
- **The full-duplex framing of the cipher budget** is the right one for a relay, and its arithmetic is right.
- **The RTO-versus-SACK derivation** in Podium 1's Stage 2 is sound protocol reasoning, and it reproduces the comment at `cmd/winn-datapath/winn3_frame_device.go:89-96` nearly clause for clause.
- **Podium 1's concession that RPS `3f` steers onto the reserved IRQ cores** closes that item. Mask `0f` is now unanimous.
- One thing Podium 1's GSO/GRO concession implies that neither of us stated: **GRO coalesces inside NAPI, on the interrupt CPU, before RPS steers.** On this node that gives CPU 4 the driver poll plus coalescing, and hands CPUs 0 through 3 one stack traversal per superframe instead of 46. Mask `0f` and GRO are complementary, not competing.

### I.8 Absorbed from Podium 2 on method

Readback discipline on every kernel request (`getsockopt` after `setsockopt`, `F_GETPIPE_SZ` after `F_SETPIPE_SZ`, `ss -u -n -m -p`), `nstat -az` deltas rather than absolute counters, per-socket packet counters to prove reuseport distribution actually happened, `tc -s qdisc` counters read before touching the qdisc, and refusing `--queue-bypass` unless fail-open is explicit policy. Adopted in full. The repo turns that last judgment into an enforced invariant at `server/wins_core_server_setup_ONETOUCH.sh:2238-2239`.

---

## Part II: Defended Grounds

### II.1 The `routeQUIC` locked scan remains the binding serialization point. Re-verified verbatim.

Podium 2 challenged my *remediation* (§I.3, conceded). Neither podium challenged the *finding*. It stands, and I re-read it this stage at `cover_demux.go:284-299`:

```go
	s.cidMu.Lock()
	defer s.cidMu.Unlock()
	for cid := range s.cids {
		if len(pkt) >= 1+len(cid) && string(pkt[1:1+len(cid)]) == cid {
			return true
		}
	}
```

`maxLearnedCIDs = 4096` at line 301. `cidMu` is a single process-global mutex at line 86. `conn: cover.v3` at `main.go:815`, unconditional, so every v3 datagram traverses this. `routeQUIC` is called per datagram at `cover_demux.go:220` and again at 271.

The derivation holds on the file's own premise. `cover_demux.go:32-35` bases its false-positive analysis on v3 datagrams being high entropy, so byte 0 is uniform, and the early-out at line 288 fails when bit 7 is clear and bit 6 is set:

$$P(\text{locked scan}) = \tfrac{1}{2}\times\tfrac{1}{2} = 0.25$$

$$0.25 \times 85{,}150 \text{ pps} \times 4096 = 8.72\times10^{7} \text{ comparisons/s}$$

$$\frac{2\times10^{9}}{8.72\times10^{7}} = 22.9 \text{ cycles per comparison}$$

A bounds check, a length compare, a `memcmp`, and a Go map iterator advance do not fit in 23 cycles, and the pump also has to issue the `recvmmsg`, classify, and hand off. **Fortification neither peer has answered:** every tuning control both podiums prescribed is already deployed at or above their recommended values (`wins_data_plane_setup_ONETOUCH.sh:4235-4241` gives `rmem_max` and `wmem_max` at 134217728 and `rps_sock_flow_entries` at 65536; line 6800 gives `rps_flow_cnt` 16384; lines 6805-6807 write a full-core mask to every `rps_cpus` and `xps_cpus`), and the node still collapses. A hypothesis that survives having its entire remediation already in production is not a hypothesis anymore.

### II.2 The batch is destroyed one datagram at a time. Re-verified.

`ReadBatchFrom` fills 32 slots in one `recvmmsg` (`cover_demux.go:147, 189`). Then `cover_demux.go:207-233` pushes each datagram into `side.incoming` individually, and `recv()` pulls each one back out inside a four-arm `select` (`cover_demux.go:420-455`). The syscall rate fell 32x. Nothing else did. 170,300 `runtime.hchan.lock` acquisitions per second at a gigabit, on one channel shared across two Ps.

This is the "demux lock contention" the deliberation asks about, and it is not a `sync.Mutex` anywhere in the source. Grepping for `Lock()` will never find it.

```go
// incoming carries BATCHES, not datagrams. One recvmmsg produced up to
// demuxBatchSize datagrams and the old code pushed and popped each one
// individually: two hchan lock acquisitions per datagram, 170,300 per second at
// a gigabit, across two Ps. pending is touched only by the single reader
// goroutine, so draining it needs no synchronization at all.
type demuxSide struct {
	split    *splitUDP
	incoming chan []demuxDatagram
	wake     chan struct{}
	pending  []demuxDatagram

	readDeadlineUnixNano atomic.Int64
}

func (d *demuxSide) recv() (demuxDatagram, error) {
	for {
		if len(d.pending) > 0 {
			pkt := d.pending[0]
			d.pending[0] = demuxDatagram{}
			d.pending = d.pending[1:]
			return pkt, nil
		}

		var timeout <-chan time.Time
		var timer *time.Timer
		if ns := d.readDeadlineUnixNano.Load(); ns != 0 {
			delay := time.Until(time.Unix(0, ns))
			if delay <= 0 {
				return demuxDatagram{}, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(delay)
			timeout = timer.C
		}
		select {
		case batch, ok := <-d.incoming:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return demuxDatagram{}, net.ErrClosed
			}
			d.pending = batch
		case <-timeout:
			return demuxDatagram{}, os.ErrDeadlineExceeded
		case <-d.wake:
			if timer != nil {
				timer.Stop()
			}
		case <-d.split.done:
			if timer != nil {
				timer.Stop()
			}
			return demuxDatagram{}, net.ErrClosed
		}
	}
}
```

The `atomic.Int64` also retires defended ground II.3 below.

### II.3 Two per-datagram costs on the hot path that do nothing. Both re-verified, and the carrier itself corroborates one.

**The dead allocation.** `cover_demux.go:217`:

```go
na: net.UDPAddrFromAddrPort(msgs[i].Addr),
```

`na` is read only by `demuxSide.ReadFrom`, at `cover_demux.go:410`. The v3 read loop calls `ReadFromUDPAddrPort` (`main.go:1714`), which returns `pkt.addr` and never touches `na` (`cover_demux.go:364-374`). Two heap objects per datagram, roughly 64 bytes, pure waste:

$$85{,}150 \times 64 = 5.45 \text{ MB/s of garbage against } \texttt{GOMEMLIMIT=96MiB}$$

**Corroboration the carrier supplies, which I did not have in Stage 2.** `udp_batch_unix.go:83-91` documents removing this exact pattern one layer down:

> `ReadBatch` used to publish `&net.UDPAddr{IP: make(net.IP, 4), ...}` for every datagram on an unconnected socket, which is two heap objects per packet: 961,000 of them in a three-second gigabit transfer.

And `udp_batch_unix.go:455-461` documents the companion fix at "5,527,000 of the 7,146,000 objects the whole run allocated, 77% of everything." The carrier eliminated per-datagram address allocation on measured evidence. The demux re-added it one layer up, in the same tree. Delete the field; build the `*net.UDPAddr` lazily inside `ReadFrom`, which is the only caller that wants it.

**The mutex guarding a constant.** `cover_demux.go:420-424` takes `d.mu` on every `recv()` to read `readDeadline`. `main.go:1717` and `main.go:1729` clear that deadline to the zero value after the readiness probe and nothing sets it again in steady state. 85,150 lock and unlock pairs per second to read a zero. Retired by the `atomic.Int64` in II.2.

### II.4 Drop semantics: the shipped split is correct, both peers err in opposite directions, and I adjudicate the residual dispute.

Re-verified. `winn3_frame_device.go:85-98` carries the design note and the measurement. Line 259-260 documents the parameter. `push` at line 269 branches on `dropOldest` at line 275. `toEngine` gets `false`, `toHost` gets `true`.

Podium 1 asked for a change to `toEngine` that is already made, and for a regression on `toHost`. Podium 2 asked for a regression on `toEngine`, which is the precise change whose absence the file's measurement documents: "the uplink sat between 21.5 and 255 Mbps," a figure that appears in the deliberation's own handset telemetry.

**Adjudicating the residual.** Podium 1 demands Podium 2 "formally concede" that drop-oldest necessarily forces an RTO. Podium 2 refuses the categorical form while adopting tail drop anyway. **Podium 2 is technically right and Podium 1 is operationally right.** A head loss is not unconditionally an RTO: subsequent segments do generate duplicate ACKs carrying SACK blocks above the hole, and a sender with enough data in flight can fast-retransmit. What Podium 1's mechanism actually establishes is the behavior under a *persistently full* queue, where the drops recur and the in-flight window that would produce those duplicate ACKs is itself being truncated. That is the measured 21.5 to 255 Mbps regime, and it is the regime this queue operates in at saturation.

Both arguments terminate at the shipped configuration. **I defend the code unchanged: no edit to either queue.** Podium 2's instrumentation list (queue drops, inner retransmissions, duplicate ACKs, RTO count, minimum cwnd, teardown count) is adopted as the regression guard, not as a precondition for a change nobody should make.

### II.5 Promoted to Tier 1 this stage: the transmit qdisc is implicated, it has a bigger measured counter than the receive side, and no podium mentioned it.

This was my Stage 2 Tier 3 hypothesis with a cheap test. The tree already ran the test.

`udp_batch_unix.go:392-408`:

> ENOBUFS IS RETRIED, BOUNDED, RATHER THAN REPORTED. It is neither a socket failure nor a peer failure: the transmit path momentarily has no room, which on this deployment is a single-tx-queue virtio NIC behind an fq qdisc with a 256-packet per-flow limit. [...] MEASURED on the Canada node, 2026-09-17: `/proc/net/snmp` reported SndbufErrors 263,060.

Confirmed on the other side: `fq_flow="256"` at `server/wins_data_plane_setup_ONETOUCH.sh:6819`, applied at line 6824 and 6837.

**263,060 SndbufErrors is 2.7 times the 96,200 `udp_rcvbuf_errors` in the deliberation telemetry.** The entire debate has been receive-side. The larger measured counter is on transmit.

The gateway-to-client downlink is one UDP 4-tuple, so it is one `fq` flow, and 256 packets is:

$$\frac{256}{85{,}150} = 3.01 \text{ ms at 1 Gbps}, \qquad \frac{256}{170{,}300} = 1.50 \text{ ms at 2 Gbps}$$

A 1.5 ms transmit queue for a multi-Gbps tunnel flow. The code currently masks it with eight bounded ENOBUFS retries (line 408), which converts qdisc backpressure into write-loop latency and, as the comment says, exists because reporting it would silently lose a whole sealed batch whose `sendCounter` has already advanced.

The override is already wired. Set `WAN_FQ_FLOW_LIMIT=2048`, which is 12.0 ms at 2 Gbps and stays well inside `limit 20480`. Read `flows_plimit` from `tc -s qdisc show dev ens3` and `SndbufErrors` from `nstat` before and after. Inner TCP runs its own congestion control, so the outer queue wants to be shallow but not shallower than one scheduling quantum of burst.

### II.6 GSO and GRO stay the multi-Gbps lever. Sequenced, not deferred.

Podium 2's objection was to my implementation, not the mechanism, and it was right. Here is the receive implementation Podium 2 correctly noted I never provided.

**Step one, the prerequisite.** Give `RawBatchConn.ReadBatchFrom` per-slot control buffers and report the coalescing size:

```go
// groControlLen is one cmsghdr plus one int, aligned. The kernel reports the
// UDP_GRO coalescing segment size here and nowhere else, so a receive path with
// hdr.control == nil cannot tell a coalesced superframe from one large
// datagram.
var groControlLen = unix.CmsgSpace(4)

// In ReadBatchFrom's per-slot setup, replacing lines 743-744:
	c.rhs[i].hdr.control = &c.rctl[i][0]
	c.rhs[i].hdr.controllen = uint64(groControlLen)

// And in the post-syscall loop, after msgs[i].N is set:
	msgs[i].GSOSize = 0
	if c.rhs[i].hdr.flags&int32(unix.MSG_CTRUNC) == 0 &&
		c.rhs[i].hdr.controllen > 0 {
		msgs[i].GSOSize = groSegmentSize(
			c.rctl[i][:c.rhs[i].hdr.controllen],
		)
	}

// groSegmentSize returns the coalescing segment size the kernel reported, or 0
// when this message was not coalesced. A non-coalesced receive carries no
// UDP_GRO cmsg at all, so 0 is the correct and safe default on every parse
// failure.
func groSegmentSize(ctl []byte) int {
	msgs, err := unix.ParseSocketControlMessage(ctl)
	if err != nil {
		return 0
	}
	for i := range msgs {
		if msgs[i].Header.Level != solUDP || msgs[i].Header.Type != udpGRO {
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

**Step two, the split, and the memory invariant it has to respect.** Raising the pump iovec to 64 KiB naively re-opens the arithmetic that `cover_demux.go:46-62` carefully solved: `2 × 4096 × 65536 = 512 MiB` of queueable memory against `GOMEMLIMIT=96MiB`. Two pools resolve it. The 64 KiB buffers belong to the pump and never enter a queue, so only `demuxBatchSize` of them exist:

$$32 \times 65{,}536 = 2 \text{ MiB, pump-resident}$$

and the queues keep holding 4096-byte segment buffers exactly as before, preserving the `2 × 4096 × 4096 = 32 MiB` worst case the file established.

```go
// A coalesced receive carries N logical datagrams of segSize bytes with a
// possibly shorter final one. Each is an independent Winn3 or QUIC datagram and
// must be classified and opened independently: handing the whole superframe to
// the v3 decoder fails AEAD verification and reads as a FORGERY, not as an
// oversize datagram, which is the confusion the maxRecvDatagram comment exists
// to prevent.
//
// Each segment is copied into its own 4096-byte pooled buffer rather than
// aliasing the superframe. That costs one ~1400-byte memcpy, on the order of a
// hundred cycles, against the ~21,968 cycles of kernel stack traversal the
// superframe just avoided. It buys trivially correct buffer ownership and it
// keeps the queued-memory invariant above intact. The saving GRO delivers is
// kernel-side; spending a userspace memcpy to collect it is the right trade.
func (s *splitUDP) explode(
	super []byte,
	segSize int,
	addr netip.AddrPort,
	out []demuxDatagram,
	scratch *[2][aes.BlockSize]byte,
) []demuxDatagram {
	n := len(super)
	if segSize <= 0 || segSize >= n {
		segSize = n
	}
	for off := 0; off < n; off += segSize {
		end := off + segSize
		if end > n {
			end = n
		}
		seg := super[off:end]
		if len(seg) == 0 || len(seg) > demuxDatagramMax {
			continue
		}
		bp := demuxBufPool.Get().(*[]byte)
		pkt := (*bp)[:len(seg)]
		copy(pkt, seg)
		out = append(out, demuxDatagram{
			b:       pkt,
			poolBuf: bp,
			addr:    addr,
			quic:    s.routeQUIC(pkt, scratch),
		})
	}
	return out
}
```

The pump then groups by destination side and does one channel send per side per `recvmmsg`, which is the II.2 change. Transmit GSO attaches the `UDP_SEGMENT` cmsg per message in `WriteBatchTo`, using the same control vectors, and only for v3 batches, never for quic-go's writes.

**Ordering is not negotiable.** `MSG_TRUNC` handling and the 64 KiB iovec land first, the cmsg parse second, the split third, and `setsockopt(UDP_GRO)` **last**. Setting the option before the split exists is the shredding scenario in §I.1.

### II.7 Unchanged, unchallenged, re-verified this stage

| Position | Evidence re-read | Status |
|---|---|---|
| XRay `bufferSize` is `4096`, meaning 4 MB; `4194304` would request 4 GiB | `VpnTunnelService.kt:1996-1997, 2012` | Defended. Do not change. |
| AWG inner MTU 1440, MSS clamp 1400 with pmtu backstop | `lib/main.dart:286-287`; `wins_data_plane_setup_ONETOUCH.sh:7223-7232` | Defended. Already optimal for a 1500-byte IPv4 outer path. |
| Lockout maximum is 300 seconds and cannot be extended by further attempts | `lib/local_security.dart:445-447, 495-499` | Defended. Wait 300 s, stop rebooting, enter `142536` once. |
| `pm clear` is the duress-wipe primitive | `MainActivity.kt:254-256` | Rejected. Destroys credential, config, subscription, Keystore. |
| `rearmAfterMonotonicRollback` is control M-15, not a bug | `lib/local_security.dart:404-414, 486-502` | Defended. Clearing on rollback is an unlimited-attempt oracle. |
| Cipher suite stays pinned | suite id `winn3-x25519-mlkem768-chacha20poly1305-sha256` | Defended. 0.05 core does not buy negotiable cryptography. |
| No cleartext lane identifier | `cover_demux.go:34-35, 75-76` | Defended. AEAD protects integrity, not observability. |
| Accept TCP 443 before NFQUEUE; never `--queue-bypass` | `wins_core_server_setup_ONETOUCH.sh:481, 2238-2239, 2563-2564` | Ratified unanimously. Fail-open is preimage-refused. |
| Android TUN pump already drains bursts at `URGENT_AUDIO` | `WinnV3AndroidTun.kt:79-80, 112, 289, 320, 358-388, 410-421, 480-506` | Defended. Re-measure; check cpuset before touching priority. |

`SO_REUSEPORT`, `UDP_SEGMENT`, and `UDP_GRO` remain absent from the entire `winn_protocol_experimental` tree. Re-confirmed by grep this stage.

---

## Part III: Irreconcilable Delta

Podium 2 holds that no cause may be named until `perf`, per-CPU softirq utilization, and a teardown-reason field arrive, which makes instrumentation the first commit and every fix conditional on it. I hold that a re-verified O(n) locked scan over as many as 4096 strings, running on one in four datagrams inside a 22.9-cycle budget, is already a proof, and that a profile confirms it rather than discovers it; the deciding evidence is that every control Podium 2 prescribes is already deployed at or above its recommended value and the node still dies. The delta is therefore not a technical disagreement about mechanism but a disagreement about burden of proof that fixes the work order: Podium 2 profiles first and patches second, I patch the four Tier 1 per-datagram costs first and profile to verify, and the secondary split follows from it, since Podium 2 would add `SO_REUSEPORT` workers now for multi-session scale while I defer them until a single session can fill the pipe.

---

## Position Lock: ranked execution order

**Tier 1, the ceiling.** Stateless keyed CID router replacing the locked scan (`cover_demux.go:284-328`). Batches through the channel (`chan []demuxDatagram`). Delete the dead `na` allocation (line 217). Atomic deadline. Raise `WAN_FQ_FLOW_LIMIT` to 2048.

**Tier 2, the multi-Gbps lever.** Control-message plumbing in `RawBatchConn`, then 64 KiB iovecs and corrected `MSG_TRUNC` semantics, then the GRO split, then `setsockopt(UDP_GRO)`, then per-message `UDP_SEGMENT` on v3 batches only. In that order.

**Tier 3, settled and cheap.** RPS mask `0f` with IRQ 36 on CPU 4 and IRQ 37 on CPU 5, XPS left off a single-queue device. Accept TCP 443 before NFQUEUE with the `ip6tables` twin. Correct the stale comment at `lib/main.dart:11101`. Wait out the 300-second lockout.

**Acceptance gate.** Podium 2's gate, adopted with three additions. Record `len(s.cids)` alongside each throughput sample until the CID table is deleted, because if my diagnosis is right the collapse threshold tracks it. Capture `go tool pprof` mutex and block profiles, not only `perf lock`, because the contention is on `runtime.hchan.lock` and a Go `sync.Mutex`. And establish first whether the deliberation's 852 to 923 Mbps figures were taken before or after `pumpBatch` landed, since both were dated today and no profile can be read without knowing which binary produced them.
