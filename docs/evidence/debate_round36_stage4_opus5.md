# Round 36 stage4: claude-opus5

## Cross-examination of the four amendments

**AMENDED OI-2.** The mechanism Seat 3 raised is resolved. systemd execs the binary already under the target UID, so the open(2) on the config happens as monero-wallet; owner-matched 0600 returns a descriptor rather than EACCES. `rpc-login` is a valid boost program_options key, so `rpc-login=user:pass` in a `--config-file` is equivalent to the flag, and argv carries only the path, so `/proc/<pid>/cmdline` and `ps` no longer expose the credential. Unit at root:root 0640 is read by PID 1 as root, so no credential needs to live there. Rotation is required, not optional, since the prior value reached the journal through the deleted printf.

Two preconditions the implementation has to meet or the fix still fails with EACCES: every parent directory of the config needs the execute bit for the service UID (a 0700 root:root `/etc/monero-wallet/` defeats an owner-readable file inside it), and any `ProtectSystem`/`ReadOnlyPaths`/`ProtectHome` setting in the unit must leave that path visible to the namespace. One hardening note, not a defect: owner root, group monero-wallet at 0640 gives the same read access while denying the service the ability to rewrite its own credential file.

**AMENDED OI-18.** The arithmetic now closes. Existing keys are looked up, not inserted, so a client with a live window cannot lose it; the table never exceeds C; the only denial is on a new-key insert against a fully fresh table. Fail-closed is the right direction here, because fail-open (evicting a fresh entry) hands an attacker a window reset, which is the whole point of the limiter.

Conditions that the implementation text must state explicitly, since getting them wrong reintroduces a defect: the capacity refusal applies only on the insert path after a lookup miss, never as a table-full precheck ahead of the lookup, otherwise clients who are under their limit get spurious 429s. Saturation also needs its own counter distinct from ordinary limit hits, because a full table means an attacker with C distinct keys can lock out every new client until the oldest window expires, and that condition is invisible if both cases increment the same metric. `Retry-After` should carry the minimum remaining TTL across the table rather than a full window.

**AMENDED OI-34.** My objection is satisfied and so is Seat 3's: no path now emits bytes whose digest fails its pin. The fallback serves a different artifact that passes its own pin, the atomic pin-plus-asset deploy transaction removes the benign cause of mismatch, and 503 remains for the case with nothing reviewed to fall back to. Falsifiable test from my Turn 3 now returns reviewed bytes or 503, never the modified payload.

Residual the implementation has to carry: the fallback bytes get the identical digest check before service, with no cascade past the single previous reviewed release (the amendment's "most recent still-pinned" reads as exactly one step back, which bounds the damage). A mismatch is attacker-triggerable, so the fallback is an attacker-selectable one-release downgrade; that needs an alert rather than only a log line and a debug header, plus a bounded fallback window after which the route fails to 503 rather than serving the older release indefinitely.

**AMENDED OI-35.** The name-substitution mechanism is fixed: separate constants mean `command -v docker` is never called with `docker.io`, and my falsifiable test no longer applies. The amendment as written still breaks two ways.

First, the condition is conflated. "Install the distro packages docker.io and git when the binary or git is absent" installs both packages whenever either is missing. On a host running docker-ce from Docker's own repository that happens to lack git, `apt-get install -y docker.io git` hits the docker.io/docker-ce conflict (both ship /usr/bin/docker and declare Conflicts), and apt resolves it by removing the working docker-ce engine. The per-package test has to gate each package on its own binary: docker.io only when `command -v docker` fails, git only when `command -v git` fails.

Second, the presence test is still the wrong predicate. docker.io supplies the engine; the `docker compose` subcommand is a separate CLI plugin package whose availability and name vary by distro release. A bare `command -v docker` success therefore suppresses btcpayserver-docker's own engine and Compose provisioning path on a host where `docker compose version` exits nonzero with `'compose' is not a docker command`, and setup fails later at the first compose invocation. The gate has to test the capability (`command -v docker >/dev/null && docker compose version >/dev/null 2>&1`) or the item has to state outright that engine and Compose ownership belongs to btcpayserver-docker and pre-install neither.

---

AMENDED OI-2: ACCEPT
AMENDED OI-18: ACCEPT
AMENDED OI-34: ACCEPT
AMENDED OI-35: REJECT: the OR condition installs docker.io on a host that only lacks git, and docker.io Conflicts docker-ce so apt removes a working engine; and `command -v docker` does not establish Compose v2, so a docker.io-only host suppresses btcpayserver-docker's provisioning and fails at `docker compose`. Gate each package on its own binary and test the compose capability, or delegate engine and Compose entirely to btcpayserver-docker.
