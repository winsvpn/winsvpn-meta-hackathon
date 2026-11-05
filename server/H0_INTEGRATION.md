H0 integration corrections for the implementation review

Design section 3.20 requires a Core companion change. Fresh and re-keyed Core
site-AI tunnels consume `ssh_user` from the registration response before
constructing known-hosts and invoking autossh. Only `root` and `wins-site-ai`
are accepted. An older hub that omits the field keeps the root fallback.
Existing root enrollments are untouched. Removing an exact legacy enrollment
requires a proven non-root tunnel and separate operator authorization.

The read-only result interface from section 3.11 is delivered in H0. H3 keeps
the remaining canary client, provisioning and served-profile work. Schema
changes run in the app's `ensure_schema`. A canary captures the current identity
digest, descriptor sequence and generation before probing. It atomically
publishes one bounded result file per slug. The app validates the field set,
types, status, time, slug and current bindings before a conditional SQL update.
Until H2 stores an identity digest the identity binds as "", and a row with no
valid stored descriptor binds seq 0; the canary and the app compute the same
values, and a later identity, descriptor or generation makes the result stale.
A verdict recorded before H0 carries no binding and keeps the status-and-age
rule until the next canary run replaces it with a bound one. H2 must populate
the identity and maintain the deployment generation.

Both normal and prepublication canaries execute through the same sandbox
profile. Weekly maintenance starts the normal unit synchronously. Installer
prepublication starts the derived advisory unit synchronously and refuses an
alternate executable. Results are read-only to the app; the canary database
and app directory are read-only to both canary units.

H1's key-history writer list must omit the removed pubkey-route generator.
The installer generator and any later actual key-replacement writer remain.
The SPA helper and the generated-key, fill-only legacy environment parser are
retained as specified. Abstract AF_UNIX endpoints are named and rejected at
preflight and postflight until none remains unreviewed: listening stream or
seqpacket sockets, and every abstract datagram socket, because a datagram
server shows state 03 once any client connects to it yet stays reachable
(Sol-H0-T3-1).
No private network namespace or live host cleanup is performed by H0.

Weekly maintenance keeps its own log and status in the root-only 0700
directory /var/log/wins-weekly-maintenance and writes nothing under a path the
hub app can write. Application-log rotation is delegated to the confined
wins-hub-logrotate.service.

`h0_privileged_jobs.json` inventories every rendered execution profile,
generated helper and known dynamic entrypoint. It records interpreters,
imports, subprocesses, file operations and app-controlled data consumers.
Profiles whose dependency closure or host behavior cannot be established
locally remain H1 prerequisites. A root-owned executable name alone is not
proof of isolation.

The acceptance gate remains unverified until Tier A and Tier B establish the
real units, dependency ownership, direct authentication denial, socket
isolation, resolver rebind, canary database write denial and firewall-helper
behavior. No key placement, deployment or host contact is authorized here.
