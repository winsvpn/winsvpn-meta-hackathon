# Round 40 addendum stage1b (continuation): solpro

**1. 2000/500 plan:** Do not promise 500 Mbps tunneled upload to the phone. The measured 437 to 445 Mbps inner rate equals 87.4% to 89.0% of 500, while 470 Mbps carrier equals 94.0%. Defensible wording is “about 440 Mbps encrypted upload on the tested phone.” The measured 580 Mbps home-to-Canada path exceeds the access-plan upload by 80 Mbps, or 16%, so that path does not disprove the 500 Mbps access tier.

**2000/2000 plan:** Do not promise 1000 Mbps tunneled upload, much less 2000. Delivering 1000 Mbps inner requires about 1070 Mbps carrier, while 580 is 54.2% of that requirement and 445 inner is 44.5% of the promise. The measured 1166 Mbps down is 58.3% of 2000, so no tested result supports a 2000 Mbps tunneled claim.

**2. Item 4:** The scrubber finding changes no v3 assumption. PMTUD reacts to kernel EMSGSIZE and sends zero probe datagrams; carriers emit nothing unbidden, and keepalives are authenticated PING frames inside AEAD messages. A packet capture showing an independent PMTU probe would falsify this conclusion.

**3. Item 5:** Run adb-deployed iperf3 UDP from the phone to a wired LAN receiver, sweeping 300, 400, 500, 600, and 700 Mbps while recording receive loss and Wi-Fi retries. Sustained raw UDP above 550 Mbps while the tunnel remains near 470 carrier implicates app processing or copies; a raw plateau near 470 implicates the handset, driver, AP, or radio path.

**OI-1:** AGREE, reranked: handset/AP uplink delivery first, app processing second, Internet policing for the remote path third, and token starvation removed. The token window is receive-only, while 470 carrier is 67.9% of the phone’s calculated 692 Mbps Tx and retries are 9.2%.

**OI-2:** DISAGREE as a throughput fix. At matched rates, burst loss was no worse than paced loss at both 400 and 550 Mbps. Pacing remains only an unproven latency feature until queue-delay measurements show improvement.

**OI-3:** DISAGREE with gigabit upload promises. The best cited path result is 580 Mbps against a 1070 Mbps carrier requirement.

**OI-4:** DISAGREE that scrubber behavior forces redesign. Code verification finds zero PMTU probe datagrams.

**OI-5:** AGREE with the local raw-UDP check. Its above-550 versus near-470 outcome separates tunnel processing from phone/AP delivery without an app PIN.
