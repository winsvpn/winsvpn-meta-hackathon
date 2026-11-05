# Hardened systemd deployment

Use one service unit:

- `winn-server-file.service` is a single-controller deployment. Its exclusive
  state lock deliberately prevents a second controller from opening the file.
- `winn-server-postgres.service` supports multiple controller instances. Apply
  `schema/postgres_v1.sql` with a migration/owner role before starting the
  runtime role.
- `winn-carrier-server.service` is the optional data-plane carrier. It may run
  beside either controller shape and needs only `CAP_NET_BIND_SERVICE`, not
  `CAP_NET_ADMIN`.
- `winn-token-issuer.service` is the optional, separately operated blind-token
  issuer for anonymous carrier authorization. Do not colocate its issuance
  logs or private RSA key with the carrier.

Create the unprivileged `winn` account, install the selected unit and
`server.env`, install the statically built binaries under
`/usr/local/libexec/winn`, and place source credentials under
`/etc/winn/credentials`. Keep that directory root-owned and mode `0700`; keep
private credentials mode `0600`.

All public Winn endpoints require RFC 9849 ECH. Install the matching
`ech-server-keys.json` credential on each service and distribute its
`ECHConfigList` to clients through a separately authenticated bootstrap
channel. A missing or rejected ECH offer fails closed on the Winn profile.
The cover profile deliberately does not require ECH, because refusing a
non-ECH client is behaviour a real ECH deployment does not have.

Every unit here also loads `cover.pem` and `cover-key.pem`, and every service
**refuses to start without them, or with the wrong kind of certificate**.

What is required is an ordinary publicly-trusted ACME certificate for a real,
publicly resolvable domain you control that has no public link back to Win's
VPN, with a name different from the Winn server certificate's. It is what an
unauthenticated prober is served in place of the Winn leaf, whose issuer
Distinguished Name would otherwise identify this deployment and every other
under the same CA.

Two kinds of certificate are refused, for two different reasons. One that
**names the operator** - an EV or OV certificate, or any certificate whose
subject carries more than a Common Name - because that hands a prober the
operator's registered identity, which is worse than what it was meant to hide.
And one that **could not be a real public origin** - self-signed, a CA served
as a leaf, a `.local`/`.internal`/`.test` name, no chain, expired - because a
prober that concludes "not a real website" blocks just as fast as one that
identifies Winn. Passing the first check is not evidence of passing the second.

See `OPERATIONS.md` section 2.1. Renewal must replace both files and restart
the unit.

The `controller-pq.seed` credential must match `WINN_SUITE`: ML-DSA-65 for
`x25519-mlkem768` and `p256-mlkem768`, ML-DSA-87 for `p384-mlkem1024`.
`device-registry.json` is the v3 registry and may contain up to four overlapping
keys per algorithm for staged rotation.

For the carrier, install `carrier-server.env`, create a separate
`winn-carrier` user, and firewall `WINN_CARRIER_AWG_BACKEND` so only the local
carrier process/host can reach it. The public listener must accept both UDP and
TCP on `WINN_CARRIER_LISTEN`. Install an unexpired signed gateway manifest, its
complete append-only transparency log, an externally retained checkpoint, and
the controller pin set under root-owned, non-writable `/etc/winn/trust`. The
log may grow to 64 MiB and is therefore intentionally a read-only trust file,
not a systemd credential. The selected node's signed MASQUE authority must match
the server certificate and externally visible authority. Replace these files
as one reviewed deployment transaction before the manifest expires.

The included carrier unit is the `identity` authorization shape and therefore
loads the device CA and registry. For an `anonymous-token` listener, use a
separate port/process and unit: set the authorization mode accordingly, omit
the device CA/registry credentials and flags, and select a manifest node that
authorizes that mode and names the accepted blind-token public key. A carrier
must never receive the issuer's private RSA key or authenticated issuance log.

For the issuer, install `token-issuer.env`, create a distinct
`winn-token-issuer` user, and keep its audit stream and blind RSA private key
separate from every carrier host. Publish only the RSA public key and key ID in
the signed gateway manifest. Rate-limit issuance as an enrollment operation,
not as a per-connection operation; clients should obtain a small protected pool
of one-time token bundles ahead of network changes.

The controller units grant only `CAP_NET_ADMIN`, needed by the configured AWG
utility. Carrier and issuer units grant only `CAP_NET_BIND_SERVICE`. Confirm
the actual utility path and interface in `server.env`. Run
`systemd-analyze security winn-server-file.service` (or the PostgreSQL unit) on
the target distribution because supported sandbox directives vary by systemd
release.

Never publish the loopback admin listener. Scrape `/metrics` locally or through
an authenticated local collector. Treat `/readyz != 200`, `audit_unavailable`,
and `audit_write_failed` as paging events.
