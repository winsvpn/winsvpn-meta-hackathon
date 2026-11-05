# Stage 1 Submission: stage1_fable51

I'm working through what a rigorous technical response about optimizing Android VPN upload throughput would need to cover: the kernel datapath, MTU encapsulation overhead, VpnService behavior, and supporting code and math, while keeping the writing varied and avoiding certain stylistic tics.

I'm tracing the asymmetry between download (1554 Mbps) and upload (706 Mbps) through the tunnel on the S26 Ultra. The likely culprit is the tun device's per-syscall packet handling: reads and writes to the tun fd process one packet at a time without batching, which throttles the upload path differently than download since the app's burst reader and Go datapath interact with that syscall boundary on the way out.

At roughly 706 Mbps that's about 60k packets/second, with each syscall taking a few microseconds :  feasible but tight on a single core. One real lever is raising the tun MTU via VpnService's setMtu(), since Android supports much larger values than 1500; a bigger inner MTU (9000 or higher) would let the transport batch more data per syscall, cutting overhead substantially before the outer layer fragments back down to path MTU for Wi-Fi.

Since the gateway sits on the same LAN (192.168.4.36), the outer path is Wi-Fi-only, and Android's Wi-Fi interface typically caps at 1500 MTU even though 802.11 itself allows larger frames via A-MSDU. That leaves roughly 1432-1448 usable inner bytes per outer UDP datagram after IPv4, UDP, and Winn protocol headers :  unless Winn's protocol can carry larger inner packets by splitting across multiple outer datagrams itself.

Working through the MTU budget: with a ~32-byte Winn header, inner MTU lands around 1440, giving a TCP MSS of roughly 1400 and about 93% efficiency relative to the 1500-byte wire frame, which I want to compare against the Wi-Fi PHY's raw throughput ceiling.

For upload bottlenecks, the real suspects are the tun read path being single-threaded with a lock-per-packet issue instead of batched locking, plus the JVM's FileInputStream copy overhead when reading the tun fd -- it'd be better to hand the fd off to Go directly via syscall reads, bypassing JNI copies entirely.

On the send side, per-datagram WriteTo syscalls are expensive at 85k pps, but Go's ipv4.PacketConn WriteBatch uses sendmmsg on Linux/Android, which could cut syscall overhead dramatically if it's actually being used.

For SO_SNDBUF, the default 208 KB drains fast at 1 Gbps but Wi-Fi driver aggregation with wide channels means TX completions come in bursts, so that shallow buffer could cause spurious blocking on sendto :  bumping it to 4-8 MB would give headroom against those bursty completions.

But there's a catch: net.core.wmem_max is typically also capped at 208 KB by default on stock Android, so calling SetWriteBuffer(8MB) gets silently clamped unless the vendor raised that ceiling or the app has root to force it via SO_SNDBUFFORCE. I need to check if Samsung devices raise wmem_max above the stock default.

That gives roughly 512 KB effective, so more like a 2.5x than 36x difference: worth flagging as a correction, verified via getsockopt SO_SNDBUF and reading wmem_max. I should also check the docket's claim about SO_SNDBUF defaults and TCP autotuning, since Android's tcp_wmem settings let sockets grow sndbuf up to 4MB automatically, which undercuts the blocking-on-write argument.

Blocking on a full socket buffer with 32 threads isn't actually a bottleneck: it just means the network itself is the limiting factor, which is fine. The 512 vs 128 KB chunk size distinction is largely a red herring too: chunked encoding overhead is negligible, and a BufferedOutputStream does nothing when writes already exceed its buffer size; chunk size mainly affects how setChunkedStreamingMode's internal buffer emits headers.

The real bottleneck likely comes from packet rate: at ~706 Mbps I'm estimating around 63k pps for uploads, but ACK traffic adds another ~31k pps of tiny 52-byte packets that Go has to write to the tun interface individually: each requiring its own syscall, which could be the actual throughput limiter.

Now I'm looking at the tun read loop itself: each read syscall costs a few microseconds on a fast core, but the real overhead is the JNI boundary, since FileInputStream.read() has to cross from Java into native code every time.
