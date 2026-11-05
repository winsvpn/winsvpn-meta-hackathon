# Security Policy and Deployment Notes

## Supported security claim

Winn Protocol v2 provides strict hybrid ECDHE+ML-KEM key establishment and
requires both X.509 and ML-DSA endpoint authentication before rotating a unique
AWG peer PSK. Public protocol endpoints also require RFC 9849 ECH. The carrier
may use the same identity-bound authentication or a separately issued one-time
blind token with ephemeral ML-DSA proof of possession.

This does not mean “quantum proof.” Security still depends on correct
implementations, protected endpoints, key custody, deployment configuration,
AWG behavior, and future cryptanalysis. This code has extensive automated and
cross-implementation tests but has not received an independent cryptographic
audit.

## Rekey failure and privacy invariants

- One exclusive controller/device/peer transaction owns Prepare through
  terminal release. It is single-owner, non-transferable, and fail closed.
- PostgreSQL retains one backend session, validates its PID and exact advisory
  lock, and never requests a second pool connection for the live transaction.
- A Commit error triggers authenticated backend reconciliation. Rollback is
  allowed only after two identical exact uncommitted snapshots under the same
  live lease.
- Release ambiguity never returns success. PostgreSQL sessions with unproved
  unlock state are removed from the pool and physically closed; file-registry
  failures retain a poisoned entry.
- Mutable old/new/snapshot PSKs are cleared and excluded from errors, metrics,
  audit detail, operational logs, and latch records.
- Operational logs exclude raw/canonically encoded device identity and use a
  domain-separated per-process HMAC correlation, with a checked fixed JSON
  fallback and `{}` as the final collision-safe record.
- AWG child stdout and stderr are explicitly discarded. Secret files require
  private POSIX modes or native Windows current-owner/protected-DACL and
  no-reparse-point validation.

## Secret handling

- Keep the TLS private key, ML-DSA seed, state key, audit key, PostgreSQL DSN,
  ECH private key, blind-token issuer private key, private token bundles,
  device private material, client state, and applied PSKs out of source control.
- Use different random 32-byte values for state encryption and audit HMAC.
- On Linux, deliver service secrets through systemd credentials, a KMS/HSM
  agent, or an equivalent short-lived read-only mount. The example units use
  systemd credentials.
- Public CA, pin, registry, ECHConfigList, signed manifest, signed device
  revocation list, transparency log, checkpoint, and blind-token
  verification-key files are not confidential, but they are trust inputs. Winn
  rejects unsafe trust files and cryptographically verifies signed deployment
  objects.
- Secret inputs must be regular files with no group/other permission. Runtime
  directories must not be group/other writable.
- The PostgreSQL database never receives a plaintext PSK response, but a
  database backup plus the state key can decrypt retained response envelopes.
  Store them under separate access controls.
- AWG command output is discarded. Protocol errors and metrics never contain a
  PSK. Audit records keyed-hash device IDs.
- The `-apply-file`, insecure PostgreSQL, and startup migration paths require
  explicit lab mode and are forbidden in production.

Go cannot guarantee that all expanded private-key material is mlocked or
immediately erased from runtime-managed memory. Harden and minimize the service
host, disable core dumps, restrict ptrace, and prefer a dedicated machine or
confidential-compute/KMS integration where the risk warrants it.

## Trust and key rotation

The device registry and controller pin set support up to four keys for each
ML-DSA parameter set. Rotate without downtime:

1. Generate the new seed in the destination secure store.
2. Distribute the new public key alongside the old key.
3. Confirm all relying parties accept the overlap set.
4. Switch the active signer.
5. Observe successful rotations under the new key ID.
6. Retire the old public key after the maximum request/key recovery window.

Rotate TLS certificates independently. A forged or compromised X.509 identity
still cannot authorize a rotation without the registered ML-DSA key, and a
stolen ML-DSA key still needs a valid device certificate.

Rotate ECH configurations with an overlap window: publish the new
`ECHConfigList` through the signed manifest or trusted controller bootstrap,
confirm client availability, activate the corresponding server key, then
retire the old configuration before its distribution channel expires. Never
enable a public-ClientHello downgrade during rotation.

## Device revocation

Revoking a device is two steps. `winn-admin -action revoke` records the
decision in controller state, which stops key rotation for that device.
`winn-admin -action revocation-list` publishes a signed list that carriers
verify and enforce, which is what stops the device relaying data. **Step 1
alone does not remove data-plane access.** See `OPERATIONS.md` §8.

The list is signed with the controller ML-DSA key and verified against the same
`-controller-pq-pins` set that authenticates the gateway manifest. Carriers
therefore hold a public verification key and no control-plane credential. This
is deliberate: carrier nodes are the exposed, disposable, potentially seized
assets in this threat model and the controller is not, so having each carrier
read the revocation table directly over PostgreSQL was rejected — a single
seized carrier would have yielded database access, and data-plane availability
would have become dependent on control-plane database availability.

Device identifiers appear in the list only as salted hashes, with a fresh salt
per list, so a seized carrier does not hand over a plaintext roster of revoked
devices and two captured lists cannot be diffed to learn who was revoked in
between. This raises the cost of bulk correlation; it is not a privacy
guarantee. Device IDs are operator-chosen strings, so an adversary who can
enumerate a plausible namespace can still test candidates against the hashes.

### Staleness: what happens when distribution is blocked

A carrier that cannot fetch or cannot verify a new list keeps enforcing the
last list it verified and keeps serving every device that list does not name.
It does not deny traffic.

This is the deliberate choice, and the reasoning should be checked rather than
assumed. "Fail closed when the list is stale" sounds obviously correct, but the
adversary in this threat model can block a distribution channel — so that rule
would let them take the entire network offline by blocking one fetch, which is
a worse outcome than the gap it closes for users whose physical safety depends
on being able to connect. Soft-failing is safe here for a structural reason:
nothing un-revokes a device, so the revoked set only grows and an older signed
list is always a subset of the true one. It never wrongly denies a good device,
and it still enforces every revocation issued before its `known_good_at`
instant. Denying everyone would not make the missed revocation any more
revoked.

Fail-closed is therefore applied to the artifact, not to the traffic:

- An unverifiable, malformed, wrong-controller, or rolled-back list is rejected
  and never installed; the previously verified list stays in force.
- The list sequence is pinned and monotone, so an adversary holding the channel
  can delay a new list but can never rewind to a smaller one.
- Age is an alerting signal — `carrier_revocation_list_stale` and
  `carrier_revocation_refresh_failed` — not a denial.

`-device-revocation-require-fresh` inverts this and denies every device once
the list ages out. It re-arms exactly the kill switch described above, so it is
off by default and is intended for deliberate, temporary use during a known
compromise.

### Scope limits

- **Anonymous-token mode is out of scope by construction.** It has no stable
  device identity to revoke — that is its purpose — and bounds exposure through
  short token validity windows and single-use durable redemption instead.
  Carriers in that mode do not consult the revocation list.
- **There is no CRL and no OCSP.** A revoked device's X.509 certificate remains
  valid until expiry; revocation is enforced at the Winn authorization layer.
  Short-lived device certificates would make most of this machinery
  unnecessary and are the better long-term direction, but they require
  issuance infrastructure that does not exist yet.
- **Established sessions are not torn down** when a new list installs; the
  device is refused at its next carrier authorization.
- Propagation is not instant. Budget the publication step, your distribution
  channel, and up to `-device-revocation-reload-interval`.

The privacy-token issuer and carrier are deliberately separate trust domains.
The issuer holds device enrollment trust and the blind RSA private key; a
carrier holds only the public key, manifest, and spent-token cache. Do not
colocate their detailed logs or join them by a stable request identifier.
Private token bundles are bearer-like one-use credentials bound to an
ephemeral ML-DSA key and must use protected storage and atomic consumption.

## Operational security

- Keep the bootstrap endpoint reachable independently of the AWG peer being
  rekeyed; exact retries are the recovery mechanism.
- Refresh and append a new signed gateway manifest before expiry. Replicate the
  full receipt log and retain its latest checkpoint through a channel
  independent of the manifest fetch.
- Synchronize controller and device clocks. Alert on more than five minutes of
  skew.
- Never run two file-backend controllers. Use PostgreSQL for HA.
- Apply `schema/postgres_v1.sql` with a migration role. Do not grant DDL to the
  runtime role.
- Require PostgreSQL `sslmode=verify-full`, private CA validation, least
  privilege, encrypted backups, and tested point-in-time restore.
- Leave the admin/metrics listener on loopback. Forward metrics through an
  authenticated local collector.
- Replicate audit logs to an append-only remote system and periodically sign
  checkpoints. The local HMAC chain detects tampering but anyone holding its
  HMAC key can construct a replacement chain.
- Page on `audit_unavailable`, `audit_write_failed`, repeated PQ authentication
  or ECH failures, manifest/checkpoint rejection, unexpected token replay,
  rate/capacity exhaustion, commit errors, and AWG apply failures.
- Cover traffic is disabled by default. Enable it only for an explicitly
  selected high-risk profile after budgeting battery, bandwidth, and
  metered-data impact; it does not prevent sophisticated correlation.
- Use the hardened service unit as a starting point and validate it with
  `systemd-analyze security` on the target distribution.
- Build from a reviewed commit, run `scripts/verify.sh`, produce the CycloneDX
  SBOM and checksum manifest, and optionally sign that manifest with an offline
  SLH-DSA key.

## Vulnerability management

The release gate pins and runs Go 1.26.5, Staticcheck 2026.1, gosec v2.25.0,
and govulncheck v1.6.0. It is still a point-in-time result. Monitor:

- Go security releases;
- CIRCL and pgx releases/advisories;
- the Go vulnerability database;
- NIST/IETF updates affecting ML-KEM, ML-DSA, ECH, RSA blind signatures,
  QUIC migration/DPLPMTUD, and the hybrid TLS groups;
- AWG/WireGuard and platform tunnel advisories.

Do not auto-upgrade cryptographic dependencies in production. Review, pin,
re-run interoperability and device gates, then promote.

## Required external approval

Before describing a deployment as audited or high-assurance:

1. Commission an independent protocol/implementation review.
2. Threat-model the actual PKI, registry enrollment, KMS/HSM, database,
   observability, and incident-response systems.
3. Exercise real AWG rekey on every shipping OS and verify the bootstrap path
   survives tunnel-key transitions.
4. Run long-duration fuzzing and load/failure testing in CI and staging.
5. Complete backup/restore, signer rotation, certificate rotation, revocation,
   stuck-pending recovery, database failover, and audit-corruption drills.
6. Review manifest/transparency governance, ECH key distribution, issuer/carrier
   non-collusion assumptions, token-inventory recovery, and privacy claims.

See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) for the division between
implemented controls and deployment-owner responsibilities.
