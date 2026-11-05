# Round 36 stage4: solpro

### AMENDED OI-2

**Confirm.** POSIX mode `0600` gives the owner permissions `4 + 2 = 6`, with group and other permissions both `0`. With ownership `monero-wallet:monero-wallet` and `User=monero-wallet`, the service effective UID matches the file owner and can read the configuration. This removes the prior mechanism where a root-owned file forced the service into the `other=0` class and `open(2)` returned `EACCES`.

The amended placement also separates the relevant surfaces:

* The credential appears only in the configuration file as `rpc-login=user:pass`.
* The unit contains no credential and remains `root:root 0640`.
* The process argument contains only `--config-file=<path>`, so `/proc/<pid>/cmdline` exposes the path but not `user:pass`.
* Deleting the stdout `printf` removes that output channel.
* If the printed password was `P_old` and rotation deploys `P_new` where `P_new != P_old`, authentication against `P_new` rejects disclosure of `P_old`.

A direct acceptance test is `stat` showing owner `monero-wallet:monero-wallet` and mode `600`, followed by `runuser -u monero-wallet -- test -r <config>`. Parent directories must also grant traversal to that UID, which is independently testable with `namei -l <config>`.

### AMENDED OI-18

**Confirm.** Let capacity be `C` with `C` fresh entries and zero expired entries. For an unseen key:

1. Expired-first pruning removes `0` entries.
2. The table remains at `C`.
3. The request receives `429 rate_limited`.
4. No insertion occurs, so the table remains at `C`.
5. The set of existing windows is unchanged.

If `E >= 1` entries are expired, pruning leaves `C - E` entries. One insertion produces `C - E + 1 <= C`, so no fresh entry must be evicted.

The implementation must distinguish existing and unseen keys before applying the capacity rejection. The executable ordering is: process an existing key against its retained window; otherwise prune expired keys; if the table still has `C` entries, return 429; otherwise insert the unseen key. A capacity test with `C + 1` fresh distinct keys should show exactly `C` stored entries, one 429 response, and unchanged start times and counters for the original `C` windows.

### AMENDED OI-34

**Confirm.** Let the current asset be `B1`, its expected pin be `P1`, and the retained reviewed asset be `B0` with retained pin `P0`.

* If `SHA256(B1) = P1`, the route serves `B1`.
* If `SHA256(B1) != P1` but `SHA256(B0) = P0`, the route serves `B0`, whose bytes remain bound to a reviewed pin.
* If `SHA256(B1) != P1` and no retained asset satisfies its reviewed pin, the route returns 503 and serves no installer bytes.

Thus, every successful response has a body whose computed digest equals a reviewed digest. The fallback should recompute the retained asset digest before serving it; merely locating a versioned filename would not prove that its stored bytes remain unchanged.

The mismatch is exposed through two specified channels, the response debug header and the operations log. Atomic pin replacement prevents readers from observing a partially written digest, while the retained release covers asset and pin publication races by serving reviewed prior bytes rather than mismatched current bytes.

### AMENDED OI-35

**Confirm.** The corrected mapping has separate command and package fields:

| Executable tested | Package installed |
|---|---|
| `docker` | `docker.io` |
| `git` | `git` |

This prevents the quoted failure where `command -v docker.io` returns status `1` even though the `docker.io` package supplied the `docker` executable. The control flow is mechanically testable:

```sh
command -v docker >/dev/null 2>&1 || install_package docker.io
command -v git >/dev/null 2>&1 || install_package git
```

With both executables present, the number of package installation calls is `0`. With only `docker` absent, it is `1` for `docker.io`. With only `git` absent, it is `1` for `git`. Keeping four explicit constants, two executable names and two package names, prevents a package identifier from being substituted into an executable check.

AMENDED OI-2: ACCEPT  
AMENDED OI-18: ACCEPT  
AMENDED OI-34: ACCEPT  
AMENDED OI-35: ACCEPT
