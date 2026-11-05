# Round 37 stage1: solpro

**Basis**: I treated the reported test results as packet evidence. I did not rerun code, builds, services, or live hosts.

1. **FIX 1**: INCOMPLETE: The temporary extraction, exact-one result, symlink refusal, credential removal from the unit, log permissions, commit pin, clean checkout, and removal of the public Nginx route are internally coherent. Two proofs are missing:
   * Archive authenticity is not checked. An archive containing exactly one malicious `monero-wallet-rpc` still satisfies the exact-one and non-symlink conditions.
   * `0600 monero-wallet:monero-wallet` proves the service UID can read the file inode and other non-root UIDs cannot, but pathname access also requires execute permission on every parent directory. No `/var/lib/monero` ownership or mode is supplied. The packet reports a `systemctl is-active` gate, not a successful service start using this configuration. The 7/7 result only establishes the stated test suite.

2. **FIX 2**: DISPUTED: The capacity policy permits global denial to new clients. Let `C = RATE_BUCKET_CAP`. `C` distinct client identities can occupy all buckets for the 60 second window, after which every additional new identity receives 429. Maintaining approximately `C / 60` bucket-creating requests per second can keep the table occupied if the attacker wins each newly expired slot. Those `C` requests can deny any number of legitimate first requests during that interval. The packet does not establish that the bucket identity is non-spoofable or costly to obtain. Existing windows are no longer reset, but availability for new clients is traded away. The pre-cache map gate, paid-route 503 behavior, expired-only pruning, and byte-identical fallback answer otherwise match the stated fixes.

3. **FIX 3**: VERIFIED. Both stated CSP locations drop the listed analytics and advertising origins plus the bare `img-src https:` wildcard. The verifier accounts for all three inline blocks, one style plus two scripts, and reports all three hash-pinned. Retaining the three payment families is explicit rather than accidental.

4. **FIX 4**: INCOMPLETE: The launcher and secret-code changes are coherent, and a successful phone build proves the deleted receiver is not needed for compilation. The Play permission action remains pending. The packet explicitly says the Permissions Declaration is only “flagged as an operator requirement before next submission.” A manifest note and LAUNCHER query do not complete that external declaration. Thus the APK implementation is complete, but OI-10 is not operationally closed.

5. **FIX 5**: VERIFIED. Every registered route must pass the inventory test, while the only public paths number three: `/live`, `/ready`, and `/favicon.ico`. Therefore generated FastAPI routes such as docs can only be absent or protected if the stated test passes. An unlisted slash variant now receives 404 instead of an automatic redirect, but that follows directly from the declared exact-path deny policy. Storage waiting is bounded by `min(remaining, 0.25s)`, so one acquisition attempt cannot block longer than 250 ms. All four suites reportedly exit 0.

6. **FIX 6**: VERIFIED. Selection with `NOFOLLOW_LINKS` occurs before safety validation. A stale, empty, symlinked, or otherwise unsafe `src/release` winner therefore fails instead of silently falling back to `src/main`. That matches the stated source-set rule that release shadows main. The 18/18 contract result also checks that the former any-safe-candidate shape is absent.

7. **FIX 7**: DISPUTED: The qdisc application is one-shot rather than persistent. The waiter applies `fq` to the particular `winn3gw0` instance created during deployment. If the gateway later deletes and recreates that virtual interface, the old qdisc disappears with the old interface; the removed `net.core.default_qdisc=fq` can no longer restore it. No service hook or interface lifecycle hook is described. Secret cleanup has a second gap: it runs only after verification passes. A failed verification, interruption, or signal leaves all staged keys present because no exit trap is described. The 120 second bound and successful-path receipts do not cover either case.

8. **FIX 8**: INCOMPLETE: The current conversion is demonstrated: `1.0.16+33` becomes `1.0.16`, and 3/3 target drift cases pass. The packet does not identify parser tests for valid YAML variations such as a quoted version scalar, trailing comment, spacing change, or prerelease component. It also does not state that the derived value is checked against each browser manifest's accepted numeric version grammar. The current input is covered; future pubspec formatting and version forms are not established.

9. **FIX 9**: VERIFIED. Validation now precedes token construction. The reported runtime cases cover one valid endpoint and two material boundary failures: a disallowed routable host and port `65536`, which is exactly one above the maximum TCP or UDP port of `65535`.

10. **FIX 10**: INCOMPLETE: The stated checks establish file type, non-symlink status, root ownership, and no group or other permission bits at check time. They do not establish trusted parent directories or atomic check-and-source behavior. If any parent is rename-writable, a file can be checked and then replaced before a later pathname-based `source`. The packet does not describe sourcing through an already validated file descriptor or revalidating the opened inode. `bash -n` proves syntax only and cannot detect this race.

11. **FIX 11**: INCOMPLETE: The repository oracle now matches the stated formula. For `N` sessions, `Max = 64 MiB + 1536 KiB × N`, `High = 0.75 × Max`, and `GOMEMLIMIT = 0.80 × High = 0.60 × Max`. The full OI-3 reconciliation remains open. The Canada capture, 492485 bytes with abbreviated hash `8d269ff2...`, is [UNVERIFIED-LIVE]. The remaining MTU difference is `1440 - 1280 = 160` bytes, or 11.1 percent of the repository value, and the node-map block exists only in the repository. Those are substantive deployment differences awaiting owner action.

**PRE-WARM FINDING**: The reported throughput samples are [UNVERIFIED-LIVE]. Their arithmetic does not support a simple 90 MB queue draining for six seconds:

* One second at 704 to 766 Mbps creates `704 / 8 = 88 MB` to `766 / 8 = 95.75 MB`.
* Draining 90 MB at 257 to 301 Mbps takes `720 / 257 = 2.80s` to `720 / 301 = 2.39s`.
* Six seconds at those rates corresponds to `257 × 6 / 8 = 192.75 MB` through `301 × 6 / 8 = 225.75 MB`.
* The stated client buffers total `128 MiB + 32 MiB = 160 MiB`, or about 167.77 MB. Even a completely full combined buffer is smaller than the six-second lower bound by about 25 MB, and the initiating burst is only about 90 MB.

Most probable ranking:

1. Pacing or token bucket. A one-second burst can consume an initial allowance, followed by a roughly 300 Mbps sustained rate while tokens recover. This fits the persistent rate plateau better than a 2.4 to 2.8 second byte drain.
2. Carrier pipe inbox depth backpressure. The in-house reliability layer could prolong recovery through retransmissions, head-of-line blocking, or acknowledgement state, but it would need continuing amplification beyond the original 90 MB to explain six seconds.
3. Gateway per-peer queue. An unreported gateway queue could hold more than the client-side 160 MiB, but the packet supplies no gateway depth measurement.
4. Client socket buffer. The known client capacity is too small for six seconds at the measured rates, and the initiating burst is smaller still.
5. Cloudflare endpoint throttle. The packet links Cloudflare Tunnel to the Monero HTTP path but supplies no evidence that the UDP carrier traverses that endpoint.

The discriminating measurement is a burst-size sweep with synchronized 100 ms samples of application inbox bytes, client UDP send-queue bytes, gateway per-peer backlog, qdisc backlog, retransmission counters, and pacer token balance. At 300 Mbps, queued bursts of 22.5, 45, and 90 MB predict drain times of 0.6, 1.2, and 2.4 seconds. Linear duration identifies queue drainage. Near-zero queues with a fixed post-burst cap identifies pacing or external policing. A nonzero gateway backlog identifies the gateway location; a persistent client socket queue identifies the client location.

**NEXT**: Restart the gateway in a way that deletes and recreates `winn3gw0`, confirm its ifindex changed, then run `tc qdisc show dev winn3gw0`. Persistence of root `fq` after recreation decides the principal FIX 7 defect locally.
