# Round 40 addendum stage2 (turn 2): solpro

**OI-1:** DISAGREE. The text calls TX PHY half of RX PHY, but 1441 / 1921 = 75.0%, so TX is 25.0% below RX, not 50.0%.

**OI-2:** AGREE. At 400 Mbps, burst loss averaged 5.62% versus 5.83% paced; at 550 Mbps, burst averaged 8.22% versus 9.315% paced, so matched-rate pacing showed no capacity gain.

**OI-3:** AGREE. The best stated delivery, 580 Mbps, is only 580 / 1070 = 54.2% of the carrier rate needed for 1000 Mbps inner, and a sustained 1070 Mbps carrier result would falsify the conclusion.

**OI-4:** AGREE. Fact D finds zero PMTUD probe datagrams and AEAD-contained keepalives, so a capture showing an unsealed constant-pattern carrier emission would falsify the no-redesign finding.

**OI-5:** DISAGREE. A 550+ Mbps phone-to-LAN result cannot isolate tunnel app processing because Fact B independently measures post-LAN policing at 5% to 10% loss from 400 to 550 Mbps; a matched raw phone-to-Canada test would falsify that alternative.

**STEELMAN:** The strongest Turn 1 case was that DefaultTokenWindow imposed a send-side window/RTT ceiling and 32-packet bursts overflowed a queue, so enlarging the window or pacing should raise upload; yes, facts A to D change my position because A finds no sender window, B finds paced loss no lower than burst loss, C measures 692 Mbps calculated phone TX with 9.2% retries, and D finds zero PMTUD probe datagrams.

**NEXT:** Correct the PHY ratio to 75.0%, then run matched native UDP sweeps from the phone to both LAN and Canada to separate radio, post-LAN policing, and tunnel processing.
