# Round 40 addendum stage3 (turn 3): solpro

**OI-1:** DISAGREE. The discriminator is nonexclusive: carrier loss below 0.5%, raw LAN and Canada throughput above 550 Mbps, and tunneled throughput of 437 to 445 Mbps would satisfy its radio confirmation while OI-5 assigns the same observations to tunnel app processing.

**OI-2:** AGREE. Fact B measured equal paced and burst loss, providing zero measured capacity benefit, while paired queue-delay samples can falsify the remaining latency and jitter benefit.

**OI-3:** DISAGREE. The product wording is already falsified at this vantage because 437 to 445 Mbps tunneled is only 75.3% to 79.5% of the 560 to 580 Mbps tested path rate, not the full tested uplink rate.

**OI-4:** AGREE. Fact D observed zero pmtud probe datagrams, so the current probe format has zero transmitted bytes requiring redesign, and any future post-key diagnostic packet lacking AEAD would falsify compliance.

**OI-5:** DISAGREE. Raw throughput above 550 Mbps on both vantages with the tunnel near 470 Mbps does not isolate app processing because the unresolved rate-dependent path policing in OI-1 can also discriminate tunnel traffic, which a raw-only sweep does not test.
