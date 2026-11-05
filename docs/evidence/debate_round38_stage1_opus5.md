# Round 38 stage1: claude-opus5

## VERDICT (podium, Round 38)

### 1. Attack on the endpoint-selection interpretation

The label/number separation is clean and bimodal with zero overlap, so a noisy confound (thermal, radio, load) is already excluded. What survives is any binary variable that tracks the label perfectly and is untouched by warm-up and by carrier buffer size. Three candidates, ranked.

**H1, address-family and inner-MTU asymmetry (strongest).** `speed.cloudflare.com` is dual-stack; the cachefly target may resolve v4-only or to a v4 PoP (UNVERIFIED-LIVE for both). If happy-eyeballs picks IPv6 for the Cloudflare target only, the Global family rides a different inner path. Packet item 3 says the Android derivation is "IPv6 minus 32". WireGuard-style overhead on an IPv6 outer is 40 + 8 + 32 = 80 bytes, not 32. An under-subtraction of that size produces PMTU black-holing or per-packet fragmentation on the v6 family alone, which yields a roughly fixed multiplicative penalty that neither the 1-second warm-up nor 8 MiB versus 4 MiB carrier buffers can move. That matches the observed invariance across all three builds better than a colo-capacity story does. **Discriminator:** resolve both hostnames on-device, then rerun the Global family pinned to an IPv4 literal, and separately rerun it with the inner MTU forced to 1280. If Global rises into the 700s under either condition, the defect is local and the anycast interpretation is wrong.

**H2, validity of the fast number rather than the slow one.** CacheFly is a distribution CDN; whether its edge accepts a large POST body, and whether it acknowledges at the edge rather than at an origin, is UNVERIFIED-LIVE. If the ingest returns 405/403 after headers, or terminates locally, the app times a transfer that never crosses the measured path, and 681 to 790 is fiction. Two supporting smells: the 767/767 exact symmetry in item 3, and the fact that the corroborating "32-parallel curl test" proves aggregate capacity, not single-stream ingest honesty. **Discriminator:** log HTTP status, total bytes handed to the socket, bytes actually counted at the tun device, and TLS-handshake time separately for each family; sweep the payload from 8 MiB to 128 MiB. A number that degrades toward 250 as payload exceeds the 16 MB socket buffer identifies buffer-fill timing, not throughput.

**H3, run-order confound.** In the two ordered groups quoted, NA runs first and Global follows. A token bucket or burst allowance at the gateway egress or at the carrier would reproduce perfect label correlation whenever the rotation order is deterministic. **Discriminator:** force the rotation to run Global first, NA second, alternating across ten pairs.

**Control that collapses all three:** point both families at the same single host, keep both labels. If the label still predicts the number, the cause lives in client code keyed by family (stream count, chunk size, timer start, result gating), not in any endpoint.

Until H1 and H2 are closed, the claim "the tunnel's true upload capacity is 681 to 790 Mbps, up from 531" is not established. The honest current statement is that two target families disagree by 3x and the app cannot yet tell which one is lying.

### 2. Product fix vote: D

A pins to whichever family scores highest, which under H2 pins permanently to the fake number. B puts two numbers on screen and pushes the app's unresolved measurement bug onto the user. C is deterministic and reversible but rests on the same unproven assumption as A, and it generalizes badly (substring match on "canada" in a label).

**D, measure the tunnel, gate the result, disclose the target.**

- **Validity gate:** a run counts only on a 2xx response, a minimum of roughly 25 MiB transferred or 5 seconds of steady state, with the first slow-start interval excluded from the rate. A run failing the gate is reported as failed, never as a number. The existing null-under-256-KiB case proves the gate is already needed.
- **Primary target is the gateway itself:** an authenticated ingest endpoint on the exit node. That is the quantity the user actually cares about, it removes anycast variance, and for the high-threat population it removes a scheduled third-party connection from the exit IP that correlates user action with exit identity. This is a privacy improvement on its own terms, independent of accuracy.
- **Deterministic target per node, recorded in the result:** the detail view names what was measured against, so a changed number is explainable rather than mysterious.
- **Third-party targets demoted to fallback,** best-of-N within a single family, never mixed into one displayed figure.

D keeps C's determinism and B's honesty without shipping a second headline number, and it refuses A's premise. If the User wants a same-day stopgap from the offered set, C is the least wrong, but only shipped behind the validity gate and labelled provisional until H2 is closed.

### 3. RV-2

Recommend (b) local-only chat route: it removes third-party disclosure at the architecture level instead of relying on a suppression filter the user cannot audit, which is the only option consistent with this product's threat model.

### 4. Notes on the other verification items

Items 1 and 2 (buffer revert, warm-up revert, Go tests passing) are accepted as reported; not verifiable from this packet. Item 3 carries the possible overhead error flagged in H1, and the fleet installer default of 1280 partially defeats the dynamic derivation it sits next to (worth confirming which one wins at runtime). Item 4: with tcpdump clean on both ends and both OS firewalls accepting, the remaining surface is the provider-level cloud firewall, which on IONOS is applied outside the guest (UNVERIFIED-LIVE); confirm the rule is attached to the correct server and that it covers UDP specifically, not TCP only.
