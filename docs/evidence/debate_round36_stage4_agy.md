# Round 36 stage4: agy

### Cross-Examination of Amended Items

#### AMENDED OI-2: Monero RPC Credential Placement
The amended fix is confirmed. Under systemd, setting `User=monero-wallet` executes the daemon under UID `monero-wallet`. If `--config-file` points to a file owned by `root:root` with permissions `0600`, the kernel DAC check fails on `open(2)` with `EACCES` because the calling process UID does not match file owner UID 0 and group/other permissions are `00`. Setting ownership to `monero-wallet:monero-wallet` with mode `0600` ensures `open(2)` succeeds for the service UID while denying read access to other unprivileged accounts. Moving credentials from command-line arguments to the configuration file prevents exposure via `/proc/$PID/cmdline` and `ps`. Removing the stdout `printf` prevents credential persistence in the journal, and password rotation invalidates prior exposure.

#### AMENDED OI-18: Local Rate Limiter Eviction Policy
The amended fix is confirmed. Consider a state table with capacity $C$. When all $C$ slots hold unexpired timestamps ($T_{\text{now}} < T_{\text{expiry}}$), evicting any entry on the arrival of key $K_{C+1}$ removes an active, unexpired window. When the evicted client transmits again, the table records a cache miss and initializes a new window with full quota, allowing clients to reset rate limits by cycling addresses or causing table churn. The amended logic inspects entries and clears only expired records ($T_{\text{expiry}} \le T_{\text{now}}$). If all $C$ records remain fresh, the limiter drops key $K_{C+1}$ with HTTP 429 (`rate_limited`) without modifying state. Active client records are preserved across table saturation.

#### AMENDED OI-34: Asset Pinning and Release Verification Fallback
The amended fix is confirmed. Serving bytes when `SHA256(current) != PIN_CURRENT` breaks cryptographic integrity, allowing modified, truncated, or unreviewed binaries to reach downloaders. Hard-failing immediately causes downtime if asset distribution propagates unevenly across edge caches. Under the amended fix, an asset with a mismatched digest is not served. The edge worker instead retrieves and serves the latest verified prior release whose digest matches its pinned hash (`SHA256(prev) == PIN_PREV`), alerting operations via response headers and logging. If no valid prior pinned version is retained, the endpoint fails closed with HTTP 503. Atomic commit of asset hash and binary in release pipelines prevents version divergence.

#### AMENDED OI-35: Binary Detection and Distro Package Mapping
The amended fix is confirmed. Executable detection queries binary names in `$PATH`, while distribution package managers track package database package names. On Debian systems, package `docker.io` installs the binary `/usr/bin/docker`. Running `command -v docker.io` returns exit code 1 because no binary by that name exists in `$PATH`, causing the package manager to execute on every run regardless of whether the engine is present. Decoupling the check command (`docker`, `git`) from the installation package (`docker.io`, `git`) ensures accurate detection and eliminates redundant execution.

---

### Final Positions

AMENDED OI-2: ACCEPT
AMENDED OI-18: ACCEPT
AMENDED OI-34: ACCEPT
AMENDED OI-35: ACCEPT
