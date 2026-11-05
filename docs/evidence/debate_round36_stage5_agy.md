# Round 36 stage5: agy

### AMENDED OI-2 (Monero RPC credential placement)
Seat 3 correctly demonstrated that starting the service under `User=monero-wallet` caused `open(2)` against a `root:root 0600` configuration file to fail with `EACCES`. Setting ownership of the RPC configuration file to `monero-wallet:monero-wallet` with mode `0600` resolves the DAC permission failure directly, allowing the unprivileged daemon UID read access while denying access to other non-root system users. Keeping the systemd unit file owned `root:root` with mode `0640` and passing credentials via `--config-file` eliminates credential exposure in `/proc/<pid>/cmdline` and systemd unit metadata. Deleting stdout printing and rotating the deployed password neutralizes historical exposure.

### AMENDED OI-18 (Local rate limiter eviction)
Seat 3 proved that when all C slots hold active, unexpired timestamps, evicting the oldest entry on arrival of key C+1 destroys the rate-limit history of an unexpired client, granting them a reset window. The amended rule enforces that cache eviction occurs strictly for expired entries. If all C entries remain unexpired, incoming requests from untracked keys are rejected with HTTP 429 (`rate_limited`) without modifying existing table entries. This maintains rate limiting invariants under capacity saturation and prevents adversaries from cycling keys to flush active tracking state.

### AMENDED OI-34 (Stale asset pin vs download availability)
Seat 2 and Seat 3 established that serving unverified payload bytes when hashes mismatch destroys the security guarantee of pinned releases. The amended mechanism guarantees that downloaders only receive verified artifacts: when current bytes diverge from the pinned digest, the delivery route falls back to the most recent reviewed release whose hash matches its committed pin. The mismatch is surfaced through response debug headers and operational telemetry, falling back to HTTP 503 only when no prior reviewed release exists in versioned storage. Coupled with atomic updates to asset files and pins during deployment, this maintains release integrity without causing total download outages during pipeline rollout windows.

### AMENDED OI-35 (Docker install names)
Seat 2 showed that `command -v` searches for executable binary names rather than Debian package identifiers. Because the Debian package `docker.io` installs `/usr/bin/docker`, testing `command -v docker.io` yields exit status 1 on properly configured hosts, triggering unnecessary reinstallation passes and ignoring existing container runtimes. Splitting the binary detection target (`docker`) from the distro package names (`docker.io` and `git`) fixes the probe logic and respects pre-installed Docker environments.

AMENDED OI-2: ACCEPT
AMENDED OI-18: ACCEPT
AMENDED OI-34: ACCEPT
AMENDED OI-35: ACCEPT
