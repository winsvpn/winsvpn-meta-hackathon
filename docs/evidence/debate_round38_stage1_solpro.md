# Round 38 stage1: solpro

- **Finding verdict:** PARTIALLY VERIFIED. The packet supports a strong association between the reported family and numeric upload, but it does not establish the claimed Cloudflare colo mechanism or exclude every tunnel-state confound.

  - North America numeric uploads span 681 to 790 Mbps.
  - Global numeric uploads span 234 to 301 Mbps.
  - The nearest edges remain separated by 681 minus 301, or 380 Mbps.
  - The possible cross-family ratio spans 681 divided by 301, or 2.26x, through 790 divided by 234, or 3.38x.
  - Halving the configured carrier buffer from 8 MiB to 4 MiB did not cause a crossover. North America remained 775 Mbps while Global remained 234 and 274 Mbps.
  - Removing warm-up also did not cause a crossover. Reading the slash pairs as download/upload, North America uploads were 706, 681, and 786 Mbps while Global stayed within 234 to 301 Mbps.
  - Therefore, the label predicts the observed number better than the two tested knobs, warm-up and configured buffer size. It does not prove superiority over every unmeasured datapath variable.

- **Data qualification:** The phrase "every run measured 234 to 301" is not literally true because one Global run returned null after transferring under 256 KiB. It is true only for every numeric Global result. The claimed 15 or more runs also cannot be reconstructed from the packet: nine runs are individually represented, followed by an uncounted group of Global runs. The 790 Mbps maximum is present only in the aggregate range, while the largest individually listed North America upload is 786 Mbps.

- **Alternative hypothesis:** A deterministic run-order carryover could reproduce perfect label correlation if rotation always assigns Global to the same ordinal position after a saturating North America run. A shared rate limiter, recovery interval, or result-association race could then follow run position rather than destination. Three builds would retain the correlation if they retained the same rotation schedule.

  The discriminating measurement is a blocked randomized test with immutable run IDs:

  1. Force Cloudflare only and Cachefly only, with fallback disabled.
  2. Randomize sequences such as Global first, North America first, Global repeated, and North America repeated.
  3. Give every first run the same reconnect and idle interval.
  4. Log run ID, displayed family, actual URL, resolved IP, address family, bytes, elapsed time, and tunnel byte counters.
  5. If Cloudflare stays at or below 301 Mbps and Cachefly stays at or above 681 Mbps regardless of ordinal position, endpoint selection survives the challenge.
  6. If the first run is fast and later runs are slow regardless of forced endpoint, the run-order alternative wins.
  7. If the displayed label and actual URL ever disagree, the result-label path is defective.

- **Mechanism challenge:** Both families contain the same two services in reversed order. The packet does not log which service actually accepted each measurement. Even if forced-target testing confirms Cloudflare as the slow service, the claimed anycast colo mapping and 230 to 300 Mbps aggregate upstream cap are UNVERIFIED-LIVE. A server-side per-request limit would produce the same family bands.

  Test one upload and then 4, 8, and 32 parallel uploads to one fixed Cloudflare IP and address family. If aggregate throughput remains near 230 to 300 Mbps as concurrency rises, a shared path or endpoint aggregate limit is supported. If aggregate throughput rises toward 681 to 790 Mbps while individual requests remain slow, the aggregate-path interpretation is refuted in favor of a per-request or test-handler limit. Running the identical fixed-IP test from the gateway and through the phone would then separate exit-to-endpoint behavior from tunnel or application behavior.

- **Buffer-theory verdict:** The 4 MiB result refutes the proposition that an 8 MiB configured limit is necessary for the low Global result. It does not prove that one bandwidth-delay product cannot influence a test. At 681 to 790 Mbps, 4 MiB corresponds to approximately 49.3 to 42.5 milliseconds of data:

  \(4,194,304 \times 8 / 681,000,000 = 0.0493\) seconds.

  \(4,194,304 \times 8 / 790,000,000 = 0.0425\) seconds.

  The packet supplies no RTT or queue-occupancy measurement, so the description of 4 MiB as approximately one BDP and the claim that one BDP cannot cause the effect are not established. The supported conclusion is narrower: changing the configured limit by 50 percent did not remove the Global low band.

- **Capacity wording:** Call 681 to 790 Mbps the measured fast-target upload range, not the tunnel's singular "true upload capacity." From the 531 Mbps baseline, the arithmetic increase is 150 to 259 Mbps, or 28.2 to 48.8 percent. Attribution of that gain to JNI bulk read plus 16 MB socket buffers is not isolated because the packet gives no same-target pre-change and post-change control. The cited 32-parallel curl proof is also UNVERIFIED-LIVE because its target, bytes, duration, and measured aggregate rate are absent.

- **Product vote:** D, fixed labeled primary plus separately disclosed route diagnostics.

  1. For a Canada-labeled node, use North America as the fixed headline family because the code already creates that Canada-specific family.
  2. Display the family beside the number, for example, "North America target: 775 Mbps."
  3. Measure Global periodically and expose it as a secondary route result with its own timestamp, preferably behind a clearly labeled diagnostic control.
  4. If North America fails, report "North America target unavailable" and show the Global fallback separately. Do not replace the headline silently with 234 to 301 Mbps.
  5. Preserve per-family history rather than choosing the maximum result.

  A would select North America under every reported numeric observation because its minimum, 681 Mbps, exceeds the Global maximum, 301 Mbps, by 380 Mbps, but selecting the winner conceals the slower route. B is route-honest but places two equal-status numbers in the main interface. C usually stabilizes the headline, but a silent fallback can still change it by 2.26x to 3.38x. D keeps one comparable target identity while retaining access to the slower-path evidence.

- **Additional verification:**  
  1. The 8 MiB reversion on both dial paths and the three passing Go suites are UNVERIFIED-LIVE because no source diff, deployed hash, or test log is included.  
  2. The warm-up removal and MainActivity verdict comment are UNVERIFIED-LIVE. The no-warm measurements support only that warm-up was unnecessary for the family split.  
  3. The dynamic MTU implementation and fleet defaults are UNVERIFIED-LIVE. The stated bounds span 1440 minus 1280, or 160 bytes. The 767/767 Wi-Fi result has a zero Mbps directional difference, but one Wi-Fi observation does not verify cellular behavior or every MTU branch.  
  4. The restored Spain management state, new keys, boot enablement, and IONOS firewall state are UNVERIFIED-LIVE. The reported packet captures support "handshakes were not observed arriving," but they do not uniquely identify the IONOS whitelist. Enabling that rule and observing UDP 51820 arrival would discriminate the firewall claim.  

- **RV-2:** Choose (b), local-only chat routing, with fail-closed suppression under (c) whenever the local-only route cannot be established.
