# Control-Hub Backup Recovery Contract

Win's VPN hub archives are **state backups**, not bare-host images. A restore is
supported only in this order:

1. Recover the newest account database from the Litestream replica BEFORE
   the new installer runs, and keep it root-only off the hub until step 6.
   The nightly archive can be up to a day old; the replica is current. If
   the old hub still runs, stop writes and use the LSR restore drill's
   command there (`litestream restore -config /etc/litestream.yml -o
   <root-only path> /root/vpn_auth/vpn_users.db`). If it is gone, restore
   from a copy of the receiver's replica directory (`/srv/wins-replica/data`
   on the Core) with the same Litestream version (`litestream restore -o
   <root-only path> file://<that copy>`). A fresh install starts replicating
   its own new database to the same replica path, and the previous generation
   is subject to Litestream's retention from that moment.
2. Provision a fresh supported control-hub OS.
3. Before the installer runs, put the pre-wipe `/root/winsvpn-secrets.env`,
   `/root/winsvpn-defaults.env` and `/root/vpn_auth.env` in place (root
   0600). The runtime file keeps every runtime-owned key and the current
   Cloudflare Access service-token secret, which the installer would
   otherwise rotate, cutting management SSH to every node. Also put back
   what the installer must find before it runs: the Litestream client key
   `/root/.ssh/wins_litestream_ed25519` (it is in the archive under
   `./root/.ssh`, but the installer generates a new key when none exists and
   the receiver has not authorised a new one) and
   `/etc/winsvpn/backup-recipients.age` (public keys, never archived).
4. Run the current control-plane one-touch installer to completion.
5. Obtain the encrypted hub archive (`...tar.gz.age`), its adjacent SHA-256
   manifest, and the escrowed age identity. Before extracting any state, run:

   ```bash
   sudo WINS_RESTORE_AGE_IDENTITY=/path/to/backup-identity \
     /usr/local/bin/wins-hub-restore-preflight \
     /path/to/wins-hub-backup-HOST-TIMESTAMP.tar.gz.age
   ```

   The preflight decrypts into a root-only work file under
   `WINS_RESTORE_WORK_DIR` (default `/root`) and removes it on exit.
6. Only after that command reports `PASS`: stop `wins-hub.service`,
   `litestream.service`, `wins-dataplane-probe.timer`, `wins-hub-backup.timer`
   and the outbox timers. Then confirm that nothing still holds a hub
   database and remove the SQLite `-wal` and `-shm` files step 4 left beside
   the databases this step replaces:

   ```bash
   find /proc/[0-9]*/fd -lname '/root/vpn_auth/*.db*' 2>/dev/null
   rm -f /root/vpn_auth/vpn_users.db-wal /root/vpn_auth/vpn_users.db-shm \
     /root/vpn_auth/winn3_authority_ledger.db-wal /root/vpn_auth/winn3_authority_ledger.db-shm
   ```

   The `find` must print nothing before the `rm`: a timer's oneshot service
   can still be running after its timer stops, so stop whatever it names and
   repeat it. SQLite pairs a WAL with its database by path alone, so a WAL
   left by step 4's fresh database is replayed over the restored file the
   first time anything opens it (Litestream, the reconciliation below or the
   hub), silently replacing the restored tables with step 4's. Remove a
   database's two files only when this step replaces that database: if the
   archive holds no `./root/vpn_auth/winn3_authority_ledger.db`, leave that
   database's files in place. Now decrypt and extract the archive EXCLUDING
   `./root/vpn_auth/main.py` (the installer owns the hub code, and its drift
   guard refuses to overwrite a main.py it did not write); if the database
   from step 1 is newer than the archived one, install it as
   `/root/vpn_auth/vpn_users.db` (root 0600) instead; then start
   `litestream.service` again so it replicates the restored file. With the
   outbox timers still stopped, and before the `--deploy` rerun re-enables
   `wins-redemption-outbox.timer`, reconcile prepaid redemption mail a pre-fix
   acknowledgement left pending: the restored database can carry
   `redemption_outbox` rows still `status='pending'` whose sealed fulfillment an
   old `/api/redeem/ack` already deleted, and the first drain after the rerun
   would otherwise rotate each such account's saved setup key and email a
   replacement (finding S-HUB-01). Welcome mail written by the current build
   keeps its own sealed copy of the whole key set in
   `redemption_outbox.sealed_secret`, and an acknowledgement deliberately leaves
   it pending (the API never showed keys 2 and up), so the reconciliation skips
   every row that holds one. The restored database usually comes from an older
   build and has no such column yet, because the schema migrates only in the
   rerun, so the first command below adds the same nullable column the hub adds
   (a no-op when it is already there). Apply the idempotent reconciliation once
   against the restored database (run from a checkout of this repository at the
   deployed revision, or copy the file to the hub first):

   ```bash
   systemctl stop wins-redemption-outbox.timer wins-redemption-outbox.service
   sqlite3 -readonly /root/vpn_auth/vpn_users.db "SELECT name FROM pragma_table_info('redemption_outbox') WHERE name = 'sealed_secret';" | grep -qx sealed_secret || sqlite3 -bail -cmd '.timeout 30000' /root/vpn_auth/vpn_users.db "ALTER TABLE redemption_outbox ADD COLUMN sealed_secret TEXT;"
   sqlite3 -bail -cmd '.timeout 30000' /root/vpn_auth/vpn_users.db < server/db/reconcile_redemption_ack_outbox.sql
   test "$(sqlite3 -readonly /root/vpn_auth/vpn_users.db "SELECT COUNT(*) FROM redemption_outbox AS o WHERE o.status = 'pending' AND COALESCE(o.sealed_secret, '') = '' AND EXISTS (SELECT 1 FROM redemption_events AS e WHERE e.idempotency_key = o.idempotency_key AND e.outcome = 'fulfillment_acknowledged');")" = 0
   /usr/local/bin/litestream sync -socket /run/litestream/litestream.sock -wait -timeout 30 -json /root/vpn_auth/vpn_users.db
   ```

   Stop if the `sqlite3` command or the `test` exits non-zero (a locked
   database, or an error the CLI would otherwise print and continue past):
   acknowledged mail is still pending, so repeat these commands until both
   pass, still before the timer is re-enabled. The Litestream result must
   name that database and report equal positive
   `txid` and `replica_txid` before the rerun. The statement only cancels
   `pending` rows that already have a `fulfillment_acknowledged` event and no
   sealed mail copy, so it is a no-op on a database with none and safe to
   re-run.
7. Rerun `--deploy`. There is no separate postflight mode (`--validate` is an
   alias of `--preflight`). The rerun reloads the restored `vpn_auth.env`,
   migrates the schema, and re-verifies the Litestream barrier, the public
   canary and every postflight gate before public cutover.

The preflight fails closed unless the archive hash, paths, and member types are
safe. The root-owned manifest must name this exact archive, and both files must
be below a root-controlled directory path (a root-owned sticky ancestor such as
`/tmp` is accepted). Symlinks, hard links,
devices, FIFOs, normalized duplicate paths, non-directory parents, control
characters, and oversized archive structures are rejected before extraction;
PAX metadata is evaluated through its resolved member path rather than trusted
as an inert header. The archive must carry the recovery contract, and
the target must have a distinct fresh-installer marker created after the
backup. For every archived systemd unit, it also requires the corresponding
root-owned unit and executable generated by the fresh installer. This prevents
a partial bare restore from installing units whose `/usr/local/bin/wins-*`,
Cloudflared, or Python virtual-environment executables do not exist.

Do not extract the archive over an unprovisioned server. Do not copy the source
server's `/etc/winsvpn/hub-install-contract.env`; the backup intentionally
excludes it so that restored state cannot impersonate a fresh installation.
