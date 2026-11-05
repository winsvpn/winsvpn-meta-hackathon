# Round 40 addendum stage1: solpro

**0. Packet consistency checks**

1. D23 geometry is internally consistent. `1024 / 2 = 512` inbox slots, and `512 - 1 = 511` reorder tolerance. A 2048 inbox therefore requires `2048 x 2 = 4096` tokens. Sequence 4095 is the 4096th zero-indexed datagram, matching the pinned death shape. The reverted 2048 change was correct because clean inbox counters during 358 to 445 Mbps runs exclude inbox overflow as the observed ceiling.

2. The carrier buffer A/B supplies no monotonic socket-size effect. The 8 MiB and 4 MiB ranges overlap from 437 through 445 Mbps, and their upper endpoints differ by only `447 - 445 = 2 Mbps`, or `2 / 445 = 0.45%`. The packet supplies no sample counts or error bars, so a statistical p value cannot be calculated, but the stated material-null ruling is consistent with the ranges.

3. The UDP Mbps pairs do not arithmetically reproduce the listed loss percentages:

   * 300 to 303 implies negative loss, not 0.84%.
   * `(400 - 374) / 400 = 6.50%`, not 8.27%.
   * `(500 - 480) / 500 = 4.00%`, not 5.95%.
   * `(550 - 519) / 550 = 5.64%`, not 7.40%.

   I therefore treat the percentages as direct packet-counter measurements and the Mbps values as separately rounded rate readings. UNVERIFIED-LIVE: the packet does not state that measurement distinction. The sustained 600 to 560 through 580 result implies `3.3% to 6.7%` rate loss, which does bracket the stated roughly 5%.

**1. Ingress ceiling ranking**

**1(i).** Loss limited inner TCP is the most probable cause.

The measured ordering supports it: one TCP stream produced 310 to 350 Mbps, the tunnel produced 437 to 445 Mbps inner, and randomized UDP delivered roughly 560 to 580 Mbps. Thus UDP retained `115 to 143 Mbps` above the inner plateau. At the stated approximately 7% Winn overhead, 437 inner becomes about `437 x 1.07 = 468 Mbps` carrier, matching the reported approximately 470. A path dropping approximately 5% to 8% around that operating region can consume retransmission capacity and disturb 32 inner TCP flows even though raw UDP still reaches a higher knee.

This is the single most probable cause, but it is not yet causal proof because RV-41 used the MacBook sender, not the phone.

**1(ii).** Phone Wi-Fi radio is second.

The 1729 link rate and 905 Mbps LAN control apply to the MacBook. They do not measure the phone. UNVERIFIED-LIVE: phone link rate, phone WLAN transmit rate, and phone retry counters. A phone-specific radio ceiling near 470 carrier would fit the observed plateau while remaining consistent with the MacBook delivering 560 to 580.

**1(iii).** Winn client send path is third.

The engine offered 644 Mbps while only 437 to 445 Mbps emerged as inner throughput. The unresolved difference is `644 - 445 = 199 Mbps` through `644 - 437 = 207 Mbps`, or 30.9% through 32.1% of offered rate. That leaves the post-offer send path, encryption scheduler, AF_UNIX batching, and radio handoff open. The 644 offer makes the earliest TUN-read stage less likely than later send stages, but it does not clear the candidate as a whole.

**1(iv).** Token window 1024 is fourth.

At 1400 bytes per datagram, 1024 datagrams contain `1024 x 1400 x 8 = 11.47 Mbit`. Sustaining 470 Mbps requires the window to turn over within `11.47 / 470 = 24.4 ms`. Sustaining 600 Mbps requires 19.1 ms. If one token remains occupied for a full path feedback cycle longer than those values, the token window could bind. The packet does not supply token-retirement timing, so this remains open. Clean inbox counters exclude inbox overflow, not token starvation.

**1(v).** Gateway side is fifth.

Canada accepted roughly 560 to 580 Mbps while reporting zero `UdpRcvbufErrors`, zero `UdpInErrors`, and flat engine CPU. Relative to 470 carrier, that is `90 / 470 = 19.1%` through `110 / 470 = 23.4%` demonstrated receiver headroom. That evidence puts the gateway behind all four client or path candidates.

The ranking is killed if a direct phone run at the plateau shows less than 1% outer sequence loss at Canada, a continuously backlogged client scheduler, and carrier emission stuck near 470 Mbps. That result would remove measured loss as the primary constraint and promote the phone radio or Winn send loop.

**2. Round 41 carrier pacing**

Ratify a bounded A/B experiment, not an unconditional production default.

Pacing can plausibly recover some goodput because the route delivered 560 to 580 Mbps carrier while Winn delivered about 470. The available measured gap is 90 to 110 Mbps. It cannot establish 600 Mbps inner throughput. With 7% overhead, even 560 to 580 carrier corresponds to only `560 / 1.07 = 523 Mbps` through `580 / 1.07 = 542 Mbps` inner before any retransmission cost.

UNVERIFIED-LIVE: RV-41 sender inter-datagram timing. If that sender was already uniformly paced, a second pacer is less likely to recover throughput and may mainly reduce queue delay.

**Rate source.** Add receiver reports every 250 ms containing unique carrier bytes accepted by the engine. Form one-second delivery samples and set the bucket rate to 98% of the maximum sample from the preceding ten seconds. With the measured 560 to 580 range, that gives 549 to 568 Mbps. Permit a 5% rate probe for 250 ms every ten seconds so the estimator does not remain trapped at the current 470 Mbps operating point.

**Burst size.** Eight 1400-byte datagrams, or 11,200 bytes. At 560 Mbps, that burst serializes in `(11,200 x 8) / 560,000,000 = 160 microseconds`. Eight datagrams are also only `8 / 512 = 1.56%` of the production inbox depth.

**Placement.** Put the scheduler after AEAD packet construction and immediately before the UDP send syscall. Apply it to original data and retransmitted data so retransmission bursts cannot bypass pacing. Keep sparse control acknowledgments and keepalives on a separately bounded priority lane.

**Token-window interaction.** A send requires both bucket credit and a token-window slot. The scheduler must not reserve a token while waiting for bucket credit, because reserved idle tokens would reduce the effective 1024 window. The design does not alter the 1024 token window, 512 inbox, 511 reorder tolerance, or any D23 ceiling test.

**Proof measurement.** Run at least ten alternating 60-second phone pairs with pacing on and off, using the same inner workload and route. Record inner unique bytes, Canada unique carrier bytes, outer sequence loss, client send-queue depth, token-starved time, and RTT. Ratification requires all three conditions:

1. Paired median inner goodput rises by at least 10%, from 437 through 445 toward at least 481 through 490 Mbps.
2. The paired 95% confidence interval for the goodput difference remains above zero.
3. Receiver loss decreases without increased token-starved time.

If only queue delay falls while goodput intervals overlap, the pacer is a latency feature, not an ingress recovery.

**3. The 1000/1000 target**

The tested home-to-Canada path does not support a 1000 Mbps upload claim. Its best measured carrier delivery was 580 Mbps. A 1000 Mbps inner target at 7% overhead needs approximately `1000 x 1.07 = 1070 Mbps` carrier. The measured 580 is only `580 / 1070 = 54.2%` of that requirement.

This does
