# Round 37 stage1: claude-opus5

## ROUND 37 VERDICT

Answered from the packet alone. Every claim about file contents, test exit codes, build success, and third-party policy text is `UNVERIFIED-LIVE` (no tools, no network); I verify coherence and design, not execution.

### FIX 1: INCOMPLETE

Holds: package-name mapping, the mktemp 0700 + `-xdev` + exactly-one + symlink-refusal extraction, moving `rpc-login` out of argv and out of the unit, deleting the stdout printf, pre-created log at 0600, and the BTCPay pre-staged-commit gate are all correct and each closes its OI.

The config-file placement answers the question asked: 0600 owned by `monero-wallet` is readable by the service user and excludes everyone except root, and directory mode is irrelevant at 0600. Two gaps remain.

- **Archive integrity is absent.** The packet describes download, extract, and `install 0755` with no pinned sha256 and no signature check against Monero's signed `hashes.txt`. A root installer that fetches a binary and installs it setuid-adjacent to the payment path is the highest-value target in this file, and the extraction hardening does nothing about a substituted archive.
- **The hub access path is named but not built.** The public `/monero-rpc` block was removed and access "moves to the WireGuard management path," yet `--confirm-external-bind=0` was also deleted, which is consistent only with a loopback bind. Nothing in the packet shows a listener reachable from the WireGuard interface. As described, the hub now has no route to the wallet RPC at all.

Minor: creation order for the credential file. Unless it is created by `install -m 0600 /dev/null` (or under `umask 077`) before the secret is written, there is a window at the default umask. Also, `nginx` was added as a dependency in the same change that deleted the only nginx block cited; confirm it is still required by BTCPay rather than vestigial.

### FIX 2: DISPUTED

`bindingRequired`, the pre-cache map-tile gate, and expired-only pruning are all correct and each is a real improvement.

**The response oracle is not closed.** Making the `containsSecretRequest` reply byte-identical to the generic miss removes only the direct signal. Topic-specific answers are still suppressed for secret queries, and that suppression is itself the oracle. Failure scenario: send a query that reliably returns a topic answer, for example "how do I configure split tunneling". Then send the same query with one candidate keyword appended. Identical topic answer means the candidate is not on the list; generic miss means it is. The list is still binary-searchable at one request per candidate, with the discriminator moved one layer out. To actually close it, a secret-flagged query must return the same body the topic router would have returned, or the topic router must not be reachable by any path that the secret check also inspects.

**Residual on the refusal limiter.** Refusing a new client at `RATE_BUCKET_CAP` with zero expired entries does satisfy the stated invariant, and it converts a window-reset bypass into a lockout. That is the right trade only if the cap is large relative to distinct legitimate clients per isolate and the window is short. As described it is a cheap amplifier: an attacker who fills the map with distinct keys denies service to every new client in that isolate until the window rolls, at zero cost beyond one request per key. Evicting the nearest-to-expiry entry, or sharding the cap by a hash of the client key so one attacker cannot occupy the whole map, keeps the invariant without the lockout.

### FIX 3: INCOMPLETE

The removals are correct and the hash-pinning check passing is the right gate for inline content.

- **Two copies, no equality test.** The CSP now lives in `web/_headers` and in `_worker.js` `CONTENT_SECURITY_POLICY`. The packet reports no test asserting the two are identical. Drift here fails silently and in the unsafe direction, since whichever copy is looser wins for the routes it serves. A string-equality test between the two is a few lines and is the durable fix.
- **Payment-provider origins unverified.** Dropping the bare `img-src https:` wildcard is correct, but PayPal's button and funding-source artwork, Google Pay's frame, and Apple Pay's session endpoints each pull from origins that must now be enumerated in `img-src`, `frame-src`, and `connect-src`. `UNVERIFIED-LIVE`: I cannot check current provider origin lists. A rendering regression here is silent in tests and visible only at checkout.
- Unstated: whether `'unsafe-inline'` still appears in `script-src` alongside the hashes, and whether the policy is enforcing or report-only.

### FIX 4: INCOMPLETE

Deleting the exported `SECRET_CODE` receiver, its class, its keep rule, and updating both contract whitelists is clean and correct. The decoy-default alias flip is the right posture.

- **The reveal path for `LauncherReal` is not demonstrated.** The same change made the decoy the only enabled launcher and deleted the dialer-code trigger. If an in-app entry sequence exists in the calculator, the packet does not say so, and "phone APK built successfully" cannot show it. A build does not prove a user can reach the real UI. This is the one item where the fix could have shipped a bricked product.
- **`QUERY_ALL_PACKAGES` and the `<queries>` LAUNCHER element are redundant against the stated justification.** If the picker needs non-launchable packages (background services do carry traffic), the `<queries>` element is unnecessary; if launchable apps suffice, the permission is unnecessary and `queryIntentActivities(LAUNCHER)` replaces `getInstalledApplications`. Keeping both signals to review that the narrower option was not chosen. `UNVERIFIED-LIVE` on current Play Permissions Declaration wording for VPN split tunneling.
- Missing gate: a contract test asserting that no component with `android:exported="true"` lacks a signature-level or custom permission. The whitelist approach catches the component you removed, not the next one added.

### FIX 5: DISPUTED

Moving `decision_log_path` into the unit's `StateDirectory` is correct. Deny-by-default ahead of routing is the right shape, and the inventory test is the right idea.

**The inventory test compares route templates, the middleware compares concrete request paths.** These agree only while no registered route carries a path parameter. Add `/peer/{id}` to the router and to `PROTECTED_PATHS`: the inventory test passes, and every real request to `/peer/abc123` gets a 404 from the middleware because the literal string is not in the set. The test asserts the property it appears to assert only under a precondition it does not check. Add an assertion that no path in either set contains `{`, or switch the middleware to template matching via `app.router` resolution before admission.

On the FastAPI internals question: `/docs`, `/redoc`, and `/openapi.json` are auto-registered, so the suites passing implies they are disabled at the app level rather than merely 404'd by middleware. That is the correct outcome; state it explicitly so a later `docs_url` reinstatement fails the test loudly. Starlette's `redirect_slashes` is now dead for every path, since the redirect is issued by the router and the middleware runs first: `/live/` returns 404 rather than a 307. Acceptable for a machine-to-machine surface, worth recording.

Two unstated items. Whether `/var/lib/winsvpn-router` is created with a fallback when the process runs outside systemd, and whether the bounded slot acquire is `asyncio` or thread-blocking. A 0.25s blocking acquire from an async handler stalls the event loop and turns moderate contention into a self-inflicted 503 storm.

### FIX 6: DISPUTED

Gating the source-set winner instead of "any safe candidate anywhere" is the correct inversion, and removing `candidates.none(::isSafeNonEmptyReleaseInput)` was necessary.

**`Files.exists(path, NOFOLLOW_LINKS)` returns true for the symlink itself.** A symlink planted at the release-side path is therefore resolved as "release wins," and any subsequent open or hash that does follow links reads the target, which can sit outside the source tree. The existence check not following links is not the same as rejecting links. The gate should fail on `Files.isSymbolicLink(path)` outright, and should read content through the same non-following handle it used to decide the winner, otherwise the decision and the inspection race.

**The shadowing premise is type-dependent.** `src/release` overrides `src/main` for resources and assets, but duplicate Kotlin or Java sources across the two sets are a compilation error rather than a shadow, and manifests merge. If the gated "engine inputs" are assets or resources, the model is right. If any are sources, an unsafe `src/main` file passes the new gate while still compiling into the release artifact, which is the old defect with the sign flipped. State the file class the gate covers.

On stale leftovers: failing loudly on an unsafe stale `src/release` file is the correct behavior, not a defect.

### FIX 7: INCOMPLETE

Scoping `fq` to the one device instead of node-wide is right, and shredding staged key material with PASS/FAIL receipts after verify is a genuine improvement.

**The qdisc application is one-shot.** A 120 second bounded waiter covers first boot. It does not cover the gateway restarting and recreating `winn3gw0` later, at which point the interface silently reverts to the kernel default and the pacing behavior the deploy verified no longer holds, with nothing reporting it. Durable fixes: a udev rule keyed on the interface name, or have the gateway set its own root qdisc when it creates the device. Either survives recreation; the waiter does not.

Confirm that every shredded artifact was already installed to its runtime location before removal, in particular `ech-server-keys.json` and the static key. If any is read from the staged path at service start, the node survives verify and dies on the next restart. Also note `shred` gives no guarantee on journaled filesystems or SSDs; if staging is on tmpfs, unlink alone is equivalent.

### FIX 8: DISPUTED

Deriving the manifest version from `pubspec.yaml` and testing for drift is the right direction.

**Nothing validates that the derived string is a legal extension version.** Chrome requires one to four dot-separated integers in 0 to 65535. A pubspec version of `1.0.17-beta.1+34`, which is valid pubspec and valid semver, yields `1.0.17-beta.1` and the extension fails to load. The drift test asserts manifest equals pubspec, so it passes on the illegal value and the failure surfaces at install time. Add a grammar assertion on the stamped value, fail the build on violation, and put the full pubspec string in `version_name` where prerelease text is legal.

Also fragile against pubspec format: a quoted value, a trailing comment on the version line, CRLF, or a `version:` key appearing under another mapping. Parse the top-level mapping rather than matching the first line containing `version:`.

### FIX 9: INCOMPLETE

Validating inside `pacToken` rather than at each call site is the right placement.

Unaddressed: what the caller does with the throw. If an uncaught `TypeError` during PAC generation leaves the proxy configuration unset or reverts it, the failure mode is traffic going DIRECT, which is worse than the invalid endpoint. The fix is only complete once the caller's catch path is shown to fail closed. A `TypeError` is also the error type most likely to be swallowed by a generic guard elsewhere; a named error class is harder to lose.

One wording flag: the packet says "routable host rejected" as evidence of correct behavior. Read literally that rejects legitimate public endpoints. I read it as intending a non-routable or loopback host, but the packet as written does not say that.

### FIX 10: INCOMPLETE

Requiring a regular, non-symlink, root-owned, 0600-or-stricter file before sourcing is the right gate and closes the direct case.

Two gaps.

- **Ancestor directories are not checked.** A 0600 root-owned file inside a directory writable by a non-root user can be replaced wholesale by rename. The gate must walk every parent to `/` and require root ownership with no group or other write bit, otherwise the file-level check is decorative.
- **Stat then source is a re-resolution.** The check and the `source` each resolve the path independently. With correct ancestor permissions this is not exploitable, which is another reason the first item matters.

Confirm "0600 or stricter" is implemented as `(mode & 0177) == 0` rather than an equality test against 600, which would reject a legitimate 0400.

### FIX 11: DISPUTED

Changing a test oracle to match the implementation it tests removes the only independent statement of intent. The packet gives no measurement justifying 1536 KiB per session and no explanation of where 14336 KiB came from; it asserts the installer is current and moves the test to it. The ratio is 9.33x. If the original figure reflected a measured working set, `MemoryMax` is now sized roughly an order of magnitude under real demand and the failure appears as cgroup reclaim thrash and then OOM kills at session counts nobody tested. If the original figure was itself unmeasured, then neither number is grounded and the suite passing means only that two unmeasured constants agree.

The derived chain is internally consistent: High at 75% of Max and `GOMEMLIMIT` at 80% of High puts the Go soft limit at 60% of Max, leaving reasonable non-heap headroom. The base of 64 MiB is plausible. The per-session term is the unsupported one. Required evidence: measured RSS at a known concurrent session count, with the oracle derived from that measurement plus headroom, and the installer corrected to the oracle if they disagree.

### Already-conforming list

`UNVERIFIED-LIVE` in full. OI-6, OI-21, OI-22, OI-31, OI-40, OI-41, OI-45, and OI-47 are asserted, not shown. OI-41 and OI-31 are coupled: an exact-origin allowlist is only cache-safe because `Vary: Origin` is present, so a single test should assert both together rather than two independent observations.

## 2. Pre-warm collapse: mechanism and ranking

The reframing matters more than the ranking. A 90 MB standing queue draining at 300 Mbps empties in 2.4 seconds, so a degradation lasting six seconds and longer is not a drain transient. During the measured phase the application keeps offering full rate, so the queue is continuously refilled. What you measured is the service rate of a system already in a saturated-queue state, and the warm-up is simply what puts it there.

The arithmetic identifies the limiter. A 32 MiB in-flight window over an inflated round trip gives 33.55 MB / RTT. At 300 Mbps (37.5 MB/s) that implies RTT near 0.9 seconds, which corresponds to roughly 84 MB of standing queue draining at 93.75 MB/s. That is the warm-up burst, almost exactly. Without the warm-up, the queue builds gradually, RTT stays near 0.35 to 0.4 seconds, and 33.55 MB over that window yields 700 to 760 Mbps, which is the observed control. The same two constants reproduce both arms of your experiment.

So the mechanism: the burst converts 128 MiB of kernel buffer and 32 MiB of application buffer into self-inflicted standing delay, after which the reliability layer's fixed in-flight ceiling becomes the binding constraint and throughput settles at window over inflated RTT. Downloads are unaffected because the client receive path has no equivalent fixed application-level window and the downlink is the wider link, so no comparable standing queue forms.

**Ranking:**

- **Carrier pipe inbox depth backpressure.** Most probable. It is the only candidate that predicts the observed ratio from the stated buffer sizes without a free parameter, and it explains persistence: the queue does not drain because the sender does not stop.
- **Gateway per-peer queue.** Second, and partially the same phenomenon viewed from the other end. A per-peer upstream queue on the gateway contributes the same RTT inflation and explains the upload-only asymmetry. Distinguishing it from the first requires gateway-side depth counters, not client-side data.
- **Client socket buffer.** Third, as enabler rather than limiter. A 128 MiB `SO_SNDBUF` does not rate-limit anything; it is the storage that lets 90 MB of standing queue exist at all. Shrinking it to roughly one bandwidth-delay product, about 3.75 MB at 750 Mbps and 40 ms, removes the room for the pathology.
- **Pacing or token bucket.** Fourth, and largely refuted by your own control. A committed rate near 300 Mbps with a finite burst credit would have to carry a credit exceeding a full uncounted measurement run to leave the no-warm-up arm at 704 to 766 Mbps throughout, which makes the bucket too large to explain anything.
- **Cloudflare endpoint throttle.** Last. A remote throttle is warm-up-independent and the control arm rules it out; a UDP data plane with in-house reliability most likely does not traverse that path anyway.

**Discriminating measurement.** Instrument three per-second series on the sender during both arms: bytes in flight, the reliability layer's smoothed RTT, and the retransmission counter. Bytes in flight pinned at the 32 MiB ceiling with RTT near 0.9 seconds and near-zero retransmissions confirms window-over-inflated-RTT and rules out loss-driven collapse. High retransmissions with in-flight well below the ceiling points instead at loss and head-of-line blocking in the ordered reliable stream.

The cheapest single-knob version, if you want one experiment rather than instrumentation: rerun the identical warm-up with the application window and send buffer set to one bandwidth-delay product instead of 32 MiB and 128 MiB. Queue-depth theory predicts the collapse disappears and steady rate holds; a policer predicts no change at all. One build, one run, unambiguous either way.

The code comment in `MainActivity.kt` should record the corrected hypothesis rather than "some carrier-path buffer drains at about 300 Mbps," which attributes a fixed rate to the path when the evidence points at your own buffer sizing.

## NEXT

Run the differential oracle probe against `publicFallbackAnswer` locally. Import the module under node, pick one query that returns a topic-specific answer, then for every entry in the secret-keyword list compare the response for that query alone against the response for that query with the keyword appended. Byte-equality across all pairs means FIX 2 actually closed the leak. Any pair that differs means the keyword list is still enumerable at one request per candidate, on a live public route, and FIX 2 needs the suppression path reworked before the treaty closes. It needs no network, no root, and no deploy, and it is the only disputed item in this packet that is both externally reachable today and provable in a single command.
