# Hub compromise and g3 recovery

This runbook covers a compromised hub: the control hub lost, in either of the
two shapes design section 3.9 separates. Case 1 is an app-level compromise
with every H0 requirement met. Case 2 is a host-root compromise, where the hub
key is assumed stolen; its recovery ends in a g3 re-key of every node, so it
is the g3 runbook. Case 2's ordering is fixed and is reproduced here exactly
as section 3.9 gives it: stale key removal comes before any re-key, and the
hub verify-ring change comes last.

During Case 2, v3 is unavailable on each node from step 1 until its step 5.
That gap is accepted: after a host-root compromise every g2-signed key is
presumed exposed, so serving g2 descriptors would hand clients a profile the
attacker may be able to impersonate. v1 serves every node meanwhile; its own
credentials are rotated in the same GK4 flow.

Nothing in this runbook uses the stolen hub key. Every node is reached
through the provider console or the operator's own non-hub SSH access.

| Placeholder | Meaning |
|---|---|
| `$HUB_BASE` | the hub's fronted base URL, `https://hub.winsvpn.org` |
| `$ADMIN_TOKEN_FILE` | owner-only file holding the fleet admin token |
| `$WINS_ADMIN_TOKEN` | the fleet admin token, read from `$ADMIN_TOKEN_FILE` |
| `$SLUG` | one node slug |
| `$NODE_SSH` | the operator's own non-hub SSH target for the node |
| `$NODE_ENDPOINT_IP` | the node's registered endpoint IP |
| `$HUB_SSH` | the operator's own SSH target for the hub host |
| `$ALLOW_LIST` | the operator allow-list on the operator Mac, `~/.xprize/winn3-ceremony/operator-ssh-keys` |
| `$HUB_KEY_HISTORY` | the trusted hub key history copy from the t1 offline medium, on the operator Mac |
| `$DAILY_DIGEST` | the last trusted daily digest file |
| `$NEW_HUB_KEY_FP` | the new hub key's fingerprint in `ssh-keygen -l -E sha256` form (`SHA256:...`) |
| `$RECOVERY_RECORD` | the operator-kept recovery record file for this incident |
| `$T1_KEY` | the offline t1 ticket-signing key from the t1 ceremony |
| `$T1_PUBLIC_B64` | the t1 public key (base64, raw 32 bytes) from the trusted ceremony record |
| `$HOST_KEYS_FILE` | the operator-verified SSH host public keys of the actual target node |
| `$RECOVERY_ACTION` | `reset` after a provider rebuild, or `rekey` for an approved in-place recovery |
| `$G3_KEY_FILE` | the escrowed g3 key on the operator Mac, a raw 32-byte Ed25519 seed (`~/.xprize/winn3-ceremony/g3.key`) |
| `$WORK` | a private working directory, mode 0700 |

Files go to the hub or a node through stdin of the operator's own SSH
session (`ssh TARGET 'sudo sh -c "umask 077; cat > PATH"' < FILE`), never as
a command-line argument, and never over scp.

Before starting Case 2, collect: the t1 offline medium (the operator
allow-list, the trusted hub key history copy, the g-ring halves, the t1 key),
the last trusted daily digest, and provider console access to every node.

## Case 1: app-level compromise, with H0 met

The key is not readable by the app. What remains is a signing service
bounded by policy: renewals of pinned identities only, within rate limits,
and no new or changed identity without an unused t1 ticket for that slug,
action, endpoint IP, gateway ID and pinned host key.

Detection: the daily digest lists every ticket spend with its identity
digest; compare it with the digest the installer printed. Signer ledger
refusals, a legitimate install refused because its ticket was already
consumed (raised at an emailed priority), and the node proofs all surface
here.

Recovery is blocked until the integrated commands exist and are reviewed:
Case 1 step 2 runs the hub key prune that Case 2 step 3 describes, and
Case 1 step 5 re-keys through Case 2 step 4, so both need the integrated
`wins-hub-key-prune`, ticket-spend and node-installation commands. Run this
stop before any recovery command below; it is an interim guard, not a
recovery step:

```sh
printf '%s\n' \
    'Recovery blocked: integrated key-prune, ticket-spend and node-installation commands are required.' >&2
exit 1
```

Recovery, in order:

1. Rotate the hub SSH key. On the hub, as root, remove the old key pair and
   re-run the installer, which generates a fresh key (`ensure_hub_ssh_key`).
   The installer does not write `/etc/winsvpn/hub-key-history` yet, so append
   the new key to it by hand (a no-op when its fingerprint is already there),
   print the fingerprint for `$NEW_HUB_KEY_FP`, and copy the history to the t1
   offline medium:

   ```sh
   sudo rm -f /root/.ssh/id_rsa /root/.ssh/id_rsa.pub
   sudo bash server/wins_control_plane_setup_ONETOUCH.sh --deploy
   sudo sh -c 'f=/root/.ssh/id_rsa.pub h=/etc/winsvpn/hub-key-history
     fp=$(ssh-keygen -l -E sha256 -f "$f" | cut -d" " -f2)
     grep -qs " $fp\$" "$h" || printf "%s %s %s\n" \
       "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(cut -d" " -f1,2 "$f")" "$fp" >> "$h"
     chmod 0644 "$h"; echo "$fp"'
   ```

2. Run the hub key prune on every node. The exact command is step 3 of
   Case 2 below; it is the same tool and the same inputs.

3. Rotate the Cloudflare Access service token the hub holds
   (`TUNNEL_SERVICE_TOKEN_ID` and `TUNNEL_SERVICE_TOKEN_SECRET`, used by
   `node_ssh_command`), so the old secret cannot reach any node's management
   path. Both are runtime-owned keys: a value passed in the environment is
   ignored and the stored one kept (`wins_runtime_owned_key`,
   `reapply_operator_intent`). Delete both stored values, keep
   `CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID`, and re-run the installer; with no
   stored secret, `ensure_cloudflare_access_service_token` calls Cloudflare's
   rotate endpoint for that token, which issues a new client secret and
   revokes the old one, and stores the new pair. Neither key may be set in
   `/root/winsvpn-secrets.env` or `/root/winsvpn-defaults.env`; the block is
   one root shell, so that refusal (which prints no value) stops it before
   any runtime file is edited or the installer runs, and so does a failed
   grep. The installer sources both files as shell, so `export`, `declare -x`,
   indented and same-line assignments are all valid inputs; the check is a
   plain substring match for the key prefix and refuses any file that holds
   the text `TUNNEL_SERVICE_TOKEN_` anywhere, including in a comment. Delete
   or reword such a line before running the block:

   ```sh
   sudo bash -s -- \
       "${WINS_SECRETS_FILE:-/root/winsvpn-secrets.env}" \
       "${WINS_DEFAULTS_FILE:-/root/winsvpn-defaults.env}" <<'SH'
   set -Eeuo pipefail
   for source in "$@"; do
       if [[ -f "$source" ]]; then
           if grep -qF 'TUNNEL_SERVICE_TOKEN_' "$source"; then
               printf '%s\n' 'Remove configured service-token assignments before rotation.' >&2
               exit 1
           else
               status=$?
               [[ "$status" -eq 1 ]] || exit "$status"
           fi
       fi
   done
   for runtime in /root/vpn_auth.env /root/vpn_auth/.env; do
       if [[ -f "$runtime" ]]; then
           sed -i --follow-symlinks \
               -e '/^TUNNEL_SERVICE_TOKEN_ID=/d' \
               -e '/^TUNNEL_SERVICE_TOKEN_SECRET=/d' "$runtime"
       fi
   done
   env WINS_SECRETS_FILE="$1" WINS_DEFAULTS_FILE="$2" \
       bash server/wins_control_plane_setup_ONETOUCH.sh --deploy
   SH
   ```

   The installer log must say "Cloudflare Access management service token is
   present and refreshed."

4. Rotate the admin token, the node tokens and the admission secrets (the
   GK4 successor flow).

5. Withdraw any descriptor not explained by a ticket and the installer's
   printed digest, and re-key that node with a fresh ticket:

   ```sh
   curl -sS -X POST "$HUB_BASE/admin/nodes/winn3/descriptor" \
     -H "x-admin-token: $WINS_ADMIN_TOKEN" \
     -F "slug=$SLUG" -F "enabled=false"
   ```

   Then re-key the node as in Case 2 step 4.

No ring change is needed in this case. This case holds only while every H0
requirement (design sections 3.2 and 3.3) is met. If any is not, treat the
compromise as host-root and use Case 2 for it too.

## Case 2: host-root compromise (the g3 runbook)

After a host-root compromise every node's gateway keys and admission secret
must be presumed known, and each node itself may carry persistence planted
with root, which pruning keys cannot rule out.

### Step 1. Contain, per node

For each slug, in this order. First save the node's winn/3 registration,
because the rollback below clears `protocol_params_json`, `path_mtu` and
`carrier_classes`; the saved copy is the reference the step 5 automatic
path's profile is checked against:

```sh
printf "SELECT slug, protocol_params_json, path_mtu, carrier_classes FROM nodes WHERE slug = '%s';\n" "$SLUG" \
  | ssh "$HUB_SSH" 'sudo sqlite3 -json /root/vpn_auth/vpn_users.db' \
  > "$WORK/$SLUG.registration.json"
```

These are non-secret profile settings read from a hub that may be
compromised; check them against the operator's own deployment record. The
step 5 canary exercises the profile the automatic path supplies.

```sh
curl -sS -X POST "$HUB_BASE/admin/nodes/winn3" \
  -H "x-admin-token: $WINS_ADMIN_TOKEN" \
  -F "slug=$SLUG" -F "enabled=false"
```

This sets the sticky operator hold, bumps the deployment generation and
returns the carrier to winn/1. The carrier must go back to winn/1: the hub
never rewrites a winn/3 node to winn/1 when a check fails, so withdrawing
only the descriptor would leave the hub refusing winn/3 clients.

```sh
curl -sS -X POST "$HUB_BASE/admin/nodes/winn3/descriptor" \
  -H "x-admin-token: $WINS_ADMIN_TOKEN" \
  -F "slug=$SLUG" -F "enabled=false"
```

This withholds the envelope (`winn3_descriptor_json` becomes NULL) and keeps
the replay floor, so the node's inner router reservation drops at this step.

Stop the node's v3 gateway through the provider console or non-hub access,
so no gateway answers on an address that is no longer reserved:

```sh
ssh "$NODE_SSH" 'systemctl disable --now winn3-gateway.service'
```

From here the node serves v1 only. Record the containment in
`$RECOVERY_RECORD`.

### Step 2. Rebuild the hub, fresh, without the signer directory

Recovery is blocked until the integrated interfaces exist and are reviewed:
the signer ledger restore or reconciliation and its recovery allowance (the
H4 root CLI writes `recovery_allowance` as `{"granted", "spent"}` while the
signer reads `recovery_allowance_remaining`), `wins-hub-key-prune` on the
nodes, `WINN3_OPERATOR_SSH_KEYS_FILE`, `WINN3_RECOVERY_MODE`,
`wins-hub-floor-reset`, ticket spending and node installation. Run this stop
before any rebuild command below; it is an interim guard, not a recovery
step:

```sh
printf '%s\n' \
    'Recovery blocked: integrated ledger restore or reconciliation, allowance, key-prune, floor-reset, ticket-spend and node-installation commands are required.' >&2
exit 1
```

1. Generate a new hub SSH key, and start the new hub key history from the
   offline copy plus the new key. The current installer generates the hub
   SSH key through `ensure_hub_ssh_key`. The pubkey route does not generate
   a missing key. Append and escrow the current public key using the Case 1
   history command before staging history to nodes.

2. Install the operator allow-list through the installer input
   `WINN3_OPERATOR_SSH_KEYS_FILE`. The installer validates every line
   against the file grammar (blank lines and `#` comment lines are skipped
   and counted separately; every other line must be exactly one fingerprint
   in the form `^SHA256:[A-Za-z0-9+/]{43}$`; a 64-character hex digest is
   refused), refuses the run on a malformed line, installs the file as
   `/etc/winsvpn/operator-ssh-keys` (root 0644), and prints its SHA-256 and
   its fingerprint, blank and comment line counts.

3. Rotate the admin token and the node tokens. Rotate the Cloudflare Access
   service token in Cloudflare and in the hub env (Case 1 step 3), so the
   old token cannot reach any node's management path.

4. Set the active slot to g3 and inject g3. The installer verifies the
   injected key's public half against the g3 pinned constant from
   `tools/winn3_descriptor_ring_defines.py`, refuses otherwise, and scrubs
   the secret variable. Set the hub verify ring to g1, g2 and g3. g2 stays
   only for verification: no signer holds it, and its descriptors are
   already withheld.

5. Run the rebuilt hub with `WINN3_RECOVERY_MODE=1`.

Put the recovery inputs on the rebuilt hub, from the operator Mac. The g3
seed is wrapped as a PKCS#8 PEM and travels only through the pipe:

```sh
ssh "$HUB_SSH" 'sudo install -d -m 0700 /root/wins-recovery'
ssh "$HUB_SSH" 'sudo sh -c "umask 077; cat > /root/wins-recovery/operator-ssh-keys"' < "$ALLOW_LIST"
ssh "$HUB_SSH" 'sudo sh -c "umask 077; cat > /root/wins-recovery/hub-key-history"' < "$HUB_KEY_HISTORY"
{ printf '302e020100300506032b657004220420' | xxd -r -p; cat "$G3_KEY_FILE"; } \
  | openssl pkey -inform DER \
  | ssh "$HUB_SSH" 'sudo sh -c "umask 077; cat > /root/wins-recovery/g3.pem"'
```

The rebuild command, on the hub. The active-slot key injection input is
`WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64` (base64 of the PEM), and its only
accepted route is a root 0600 secrets file under
`/etc/wins-descriptor-signer-input`, which `wins-hub.service` cannot read,
with the installer run as `WINS_SECRETS_FILE=` that file. The installer
refuses the key from the defaults file, from any other secrets file and from
the process environment, verifies its public half against the slot's pinned
constant, refuses otherwise, and scrubs the variable. That file replaces
`/root/winsvpn-secrets.env` for this run, so the command copies the commerce
secrets into it first, writes the key line with the shell's own `printf`
(never on a command line), and removes the file after the run. The shell
refuses before it writes the file or runs the installer when the t1 key or a
ring define is empty (the staged `g3.pem` stays in place for a retry), and
when the g3 key read fails or is empty or the commerce copy fails. An exit
trap, installed before the key read, removes the input file and the staged
`g3.pem` on those later refusals and after the run.

`T1_PUBLIC_B64` must be supplied from the trusted ceremony record to that
root shell; it is a public key. The g1, g2 and g3 verification halves come
from `tools/winn3_descriptor_ring_defines.py`:

```sh
sudo install -D -m 0644 -o root -g root /root/wins-recovery/hub-key-history /etc/winsvpn/hub-key-history
sudo env T1_PUBLIC_B64="$T1_PUBLIC_B64" bash -c '
  set +x
  set -Eeuo pipefail
  [ -n "$T1_PUBLIC_B64" ] || { echo "T1_PUBLIC_B64 is empty." >&2; exit 1; }
  export WINN3_SIGNER_TICKET_PUBKEY_T1="$T1_PUBLIC_B64"

  while IFS= read -r line; do
      name="${line%%=*}"
      value="${line#*=}"
      case "$name" in
          WINS_WINN3_DESCRIPTOR_PUBKEY_G1)
              export WINN3_DESCRIPTOR_PUBKEY_G1="$value" ;;
          WINS_WINN3_DESCRIPTOR_PUBKEY_G2)
              export WINN3_DESCRIPTOR_PUBKEY_G2="$value" ;;
          WINS_WINN3_DESCRIPTOR_PUBKEY_G3)
              export WINN3_DESCRIPTOR_PUBKEY_G3="$value" ;;
      esac
  done < <(python3 -B tools/winn3_descriptor_ring_defines.py env)
  [ -n "${WINN3_DESCRIPTOR_PUBKEY_G1:-}" ] &&
      [ -n "${WINN3_DESCRIPTOR_PUBKEY_G2:-}" ] &&
      [ -n "${WINN3_DESCRIPTOR_PUBKEY_G3:-}" ] ||
      { echo "The descriptor ring defines are incomplete." >&2; exit 1; }

  input=/etc/wins-descriptor-signer-input
  cleanup_input() {
      local status=$?
      trap - EXIT
      set +e
      rm -f -- "$input/secrets.env" /root/wins-recovery/g3.pem
      local cleanup_status=$?
      unset key_pem_b64
      if (( status == 0 && cleanup_status != 0 )); then
          status=$cleanup_status
      fi
      exit "$status"
  }
  trap cleanup_input EXIT
  install -d -m 0700 -o root -g root "$input"
  key_pem_b64="$(openssl base64 -A -in /root/wins-recovery/g3.pem)"
  if [[ -z "$key_pem_b64" ]]; then
      printf "%s\n" "Empty signer key input; deployment refused." >&2
      exit 1
  fi
  ( umask 077
    rm -f "$input/secrets.env"
    {
      if [ -f /root/winsvpn-secrets.env ]; then
          grep -v "^WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64=" /root/winsvpn-secrets.env \
              || [[ $? -eq 1 ]]
      fi
      printf "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64=%s\n" "$key_pem_b64"
    } > "$input/secrets.env"
  )
  unset key_pem_b64
  status=0
  env WINS_SECRETS_FILE="$input/secrets.env" \
      WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT=g3 \
      WINN3_OPERATOR_SSH_KEYS_FILE=/root/wins-recovery/operator-ssh-keys \
      WINN3_RECOVERY_MODE=1 \
      bash server/wins_control_plane_setup_ONETOUCH.sh --deploy || status=$?
  rm -f "$input/secrets.env"
  exit "$status"
'
```

Then append the new hub key to the history and take its fingerprint as
`$NEW_HUB_KEY_FP`, with the Case 1 step 1 append command. Bring the updated
history back to the operator Mac, so step 3 stages the history that holds
the new hub key, and escrow that updated copy:

```sh
ssh "$HUB_SSH" 'sudo cat /etc/winsvpn/hub-key-history' \
    > "$WORK/hub-key-history.updated"
HUB_KEY_HISTORY="$WORK/hub-key-history.updated"
```

**Inflated retained floors (A-4).** The store path checks only `seq < 0`
and `seq <= floor`, so the host-root attacker can have raised a slug's
retained floor (`winn3_admission_sequence_floor`) above
`2^53 - 1 - 2^32` (9007194959773695), which would then refuse that slug's
recovery for good. The rebuilt hub lists every slug whose retained floor is
above that bound, or above the highest sequence in the last trusted daily
digest. For each listed slug, before that slug's re-key, reset the retained
floor to the digest value with the hub operator-root CLI:

```sh
sudo wins-hub-floor-reset --slug "$SLUG" --digest "$DAILY_DIGEST"
```

The CLI runs only as root on the hub host, only while
`WINN3_RECOVERY_MODE=1`, and never through the app. It sets
`sequence_floor`, `current.seq` and `previous.seq` in
`winn3_admission_json`, wherever they exceed the digest value, to that
value; it then re-reads `winn3_admission_sequence_floor` and refuses unless
it equals the digest value. It refuses a value above the bound, and it
writes one audit line per slug. Record every reset in `$RECOVERY_RECORD`.

### Step 3. Keep only known keys on every node, before any re-key

Reach each node through the provider console or the operator's own non-hub
SSH access. The stolen hub key is never used.

Copy the allow-list and the trusted history to the node, compare their
digests with the operator's copies (the two outputs must match), then run the
node tool the data plane installs (root 0700) on the node-side copies:

```sh
ssh "$NODE_SSH" 'sudo install -d -m 0700 /root/wins-recovery'
ssh "$NODE_SSH" 'sudo sh -c "umask 077; cat > /root/wins-recovery/operator-ssh-keys"' < "$ALLOW_LIST"
ssh "$NODE_SSH" 'sudo sh -c "umask 077; cat > /root/wins-recovery/hub-key-history"' < "$HUB_KEY_HISTORY"
ssh "$NODE_SSH" 'cd /root/wins-recovery && sudo sha256sum operator-ssh-keys hub-key-history'
shasum -a 256 "$ALLOW_LIST" "$HUB_KEY_HISTORY"
ssh "$NODE_SSH" 'sudo wins-hub-key-prune \
  --keep-sha256 "'"$NEW_HUB_KEY_FP"'" \
  --keep-list /root/wins-recovery/operator-ssh-keys \
  --history /root/wins-recovery/hub-key-history'
```

In recovery the prune works in allow-list mode: it keeps only lines whose
key matches the new hub key or a fingerprint on the operator allow-list,
whatever the line's comment, marker or options field. It removes every other
key line, marked or unmarked, duplicates included, which includes an older
hub key that exists only as unmarked lines and was never in any history. It
also removes every malformed line, never keeping one. A line whose
fingerprint is on the allow-list or equals the new hub key is never
malformed. It labels each removed line "known hub key" when the history
matches it, and "unclassified" otherwise. It installs the new hub key line,
marked, if absent. It runs under the same directory flock as the add-only
writer, writes a temp file and renames it, and prints the SHA-256
fingerprint of every remaining line and every removed line. Record those
fingerprints in `$RECOVERY_RECORD`.

Node-side check: the register heartbeat reports the total count of
`authorized_keys` key lines, the count of marked lines, the SHA-256
fingerprint of every key line, and every malformed line by line number.
Fingerprints of public keys are not secret, and the hub already reads the
file as root. Under `WINN3_RECOVERY_MODE=1`, the auto-provision job compares
them with the new hub key and the hub's copy of the allow-list at
`/etc/winsvpn/operator-ssh-keys`. It refuses any `sign` or `rekey` for a
slug until every line is one of those, no line is malformed, and the new
key is present exactly once.

Where the fleet allow-list cannot be vouched for on a particular node (an
operator key added by hand on that node only, for example), the prune is not
run in place there. Record that slug as `rebuild` in `$RECOVERY_RECORD`; the
node takes the step 4 default, a provider rebuild.

### Step 4. Re-key and re-sign every node with g3

The default is a provider rebuild of each node and a fresh install with a
t1 `reset` ticket. An in-place re-key (a rerun with `WINN3_IDENTITY_CHANGE=1`
and a t1 `rekey` ticket under the current epoch) is allowed only after step 3
passes in allow-list mode for that node, and `$RECOVERY_RECORD` records the
accepted residual for it.

Order of operations for each slug:

1. When the ledger was reconciled without a checkpoint, every slug is
   `suspended`. Spend a t1 `unsuspend` ticket for the slug under the current
   epoch first, then the `reset` or `rekey` ticket. `prepare_subject` can
   mint both in one session:

   ```sh
   case "$RECOVERY_ACTION" in
       reset|rekey) ;;
       *) printf '%s\n' 'RECOVERY_ACTION must be reset or rekey.' >&2; exit 1 ;;
   esac

   tools/wins_operator_prepare_subject.sh --role data --subject "$SLUG" \
       --hub "$HUB_BASE" --admin-token-file "$ADMIN_TOKEN_FILE" \
       --host-keys-file "$HOST_KEYS_FILE" --no-tunnel --no-grant \
       --t1-key "$T1_KEY" --action unsuspend \
       --endpoint-ip "$NODE_ENDPOINT_IP" --go-live manual --tier free \
       --out "$WORK/$SLUG.unsuspend.env"

   tools/wins_operator_prepare_subject.sh --role data --subject "$SLUG" \
       --hub "$HUB_BASE" --admin-token-file "$ADMIN_TOKEN_FILE" \
       --host-keys-file "$HOST_KEYS_FILE" --no-tunnel --no-grant \
       --t1-key "$T1_KEY" --action "$RECOVERY_ACTION" \
       --endpoint-ip "$NODE_ENDPOINT_IP" --go-live manual --tier free \
       --out "$WORK/$SLUG.$RECOVERY_ACTION.env"
   ```

   `HOST_KEYS_FILE` contains the operator-verified keys for the actual
   target. `RECOVERY_ACTION` is `reset` after provider rebuild or `rekey` for
   an approved in-place recovery. Run the unsuspend preparation only when
   reconciliation suspended the slug. These commands prepare and post
   tickets; they do not spend them or install the node. Those omissions
   remain covered by the recovery stop at the start of step 2.

   `--go-live` and `--tier` are required, with no default; the tool refuses
   to mint a ticket without them, so go-live is always an explicit choice
   recorded in the signed ticket.

2. The request carries the hub's retained floor as `expected_prior_seq`, and
   is accepted under the no-live-issuance rule for a slug with no live
   issuance. The descriptor route cannot show it: step 1 withheld the
   descriptor, so its `rotation.current_seq` is null. Read the retained floor
   (the largest of `sequence_floor`, `current.seq` and `previous.seq` in
   `winn3_admission_json`, as `winn3_admission_sequence_floor` computes it
   with no stored descriptor) on the hub:

   ```sh
   sudo python3 -I - "$SLUG" <<'PY'
   import json
   import sqlite3
   import sys

   slug = sys.argv[1]
   with sqlite3.connect(
       "file:/root/vpn_auth/vpn_users.db?mode=ro", uri=True
   ) as conn:
       row = conn.execute(
           "SELECT winn3_descriptor_json, winn3_admission_json "
           "FROM nodes WHERE slug = ?",
           (slug,),
       ).fetchone()

   if row is None:
       raise SystemExit("Node not found")
   if row[0] is not None:
       raise SystemExit("Descriptor must be withheld before this recovery query")

   ledger = json.loads(row[1]) if row[1] else {}
   if not isinstance(ledger, dict):
       raise SystemExit("Malformed admission ledger")

   values = [ledger.get("sequence_floor")]
   for name in ("current", "previous"):
       item = ledger.get(name)
       if isinstance(item, dict):
           values.append(item.get("seq"))

   floor = max(
       (value for value in values
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0),
       default=-1,
   )
   if floor > 2**53 - 1 - 2**32:
       raise SystemExit("A-4 floor reset required before issuance")
   print(floor)
   PY
   ```

   It keeps only non-negative integers, as the helper does, so a text
   `sequence_floor` such as `"99"` is ignored rather than compared.

3. The identity is signed with g3 at a new sequence above the larger of the
   ledger floor and the hub's floor, with `admission_gen` incremented.

4. Where the operator granted a recovery allowance (design section 3.12),
   each such issuance spends one unit of it, so the rate-limit window does
   not hold it back. Each issuance still needs its own ticket, and one
   identity per ticket still applies.

### Step 5. Return each node to v3 as it is ready

While the sticky operator hold is set, enabled=true clears that hold and
returns without restoring registration fields or flipping the carrier.
The reviewed automatic path must then supply the current identity's
profile, pass the bound served-profile canary and carrier candidate gate,
and commit under the current deployment generation. Hold clearance alone
is not evidence that the node serves v3.

```sh
printf 'header = "x-admin-token: %s"\n' "$WINS_ADMIN_TOKEN" |
    curl --config - --fail --silent --show-error \
        -X POST "$HUB_BASE/admin/nodes/winn3" \
        --form-string "slug=$SLUG" --form-string "enabled=true" |
    jq -e '.ok == true and .hold_cleared == true and .operator_hold == false'
```

The clearing action is a separate authorization from
signer unsuspension; the auto-provision job and the go-live flip both check
the hold first.

### Step 6. Only then, remove g2 from the hub verify ring

Wait until no stored g2 descriptor remains: each node has a stored g3
descriptor, has its g2 descriptor withdrawn with its gateway stopped, or is
retired. Step 1 already withholds every g2 envelope and stops each gateway,
so the reservation reason applies only to nodes not contained.

The ring change still comes last, for two reasons: the serve path
re-verifies every stored descriptor and rejects an unprovisioned slot, and
inner-address reservations count only descriptors that verify, so removing
g2 while any g2 row is stored would free a live gateway's inner router
address.

Concretely: the installer loads `/root/vpn_auth/.env` and then
`/root/vpn_auth.env` before it writes the ring (`load_existing_envs`), so
unsetting `WINN3_DESCRIPTOR_PUBKEY_G2` in the environment alone keeps g2.
Remove both generated runtime copies, refuse configured-source
reintroduction from `/root/winsvpn-defaults.env` or
`/root/winsvpn-secrets.env`, re-run the installer, and check the ring. A
`grep` error other than no match stops the block before any edit, and the
installer runs with the same defaults and secrets files the block checked.
The installer sources both files as shell, so `export`, `declare -x`,
indented and same-line assignments are all valid inputs; the check is a
plain substring match for `WINN3_DESCRIPTOR_PUBKEY_G2` (which also covers
the `_FILE` form) and refuses any file that holds that text anywhere,
including in a comment. Delete or reword such a line before running the
block. A retired slot stays in the ring, verification only, until no stored
descriptor of that slot remains, expired or not.

```sh
sudo bash -s -- \
    "${WINS_DEFAULTS_FILE:-/root/winsvpn-defaults.env}" \
    "${WINS_SECRETS_FILE:-/root/winsvpn-secrets.env}" <<'SH'
set -Eeuo pipefail
for source in "$@"; do
    if [[ -f "$source" ]]; then
        if grep -qF 'WINN3_DESCRIPTOR_PUBKEY_G2' "$source"; then
            printf '%s\n' 'Remove the configured g2 input before retirement.' >&2
            exit 1
        else
            status=$?
            [[ "$status" -eq 1 ]] || exit "$status"
        fi
    fi
done
for runtime in /root/vpn_auth.env /root/vpn_auth/.env; do
    if [[ -f "$runtime" ]]; then
        sed -i --follow-symlinks \
            -e '/^WINN3_DESCRIPTOR_PUBKEY_G2=/d' \
            -e '/^WINN3_DESCRIPTOR_PUBKEY_G2_FILE=/d' "$runtime"
    fi
done
env -u WINN3_DESCRIPTOR_PUBKEY_G2 -u WINN3_DESCRIPTOR_PUBKEY_G2_FILE \
    WINS_DEFAULTS_FILE="$1" WINS_SECRETS_FILE="$2" \
    bash server/wins_control_plane_setup_ONETOUCH.sh --deploy
SH

printf 'header = "x-admin-token: %s"\n' "$WINS_ADMIN_TOKEN" |
    curl --config - --fail --silent --show-error \
        "$HUB_BASE/admin/nodes/winn3/descriptor" |
    jq -e '
        .ok == true
        and (.verification_key_slots | index("g1") != null)
        and (.verification_key_slots | index("g3") != null)
        and (.verification_key_slots | index("g2") == null)
    '
```

The `jq -e` check exits non-zero unless the ring holds g1 and g3 and not g2.
This follows, and does not replace, the stored-descriptor retirement
prerequisite above.

### Step 7. Migrate the 13 legacy hub-minted device keys to client-owned keys

Device-owned v3 private keys are never exposed. The 13 legacy hub-minted
device keys remain exposed until their migration is verified, and the claim
is limited to device-owned identities.

Ship the client-key build (the build that sends its own
`winn3_static_public`), then flip the hub's mint lever off and re-run the
installer:

```sh
sudo env WINN3_HUB_MINTED_KEYS_ALLOWED=0 \
     bash server/wins_control_plane_setup_ONETOUCH.sh --deploy
```

Each legacy row migrates on its next `/verify` from a client-key build: the
hub replaces the hub-minted public key with the client's own and keeps the
address. Verify no hub-minted row remains:

```sh
sqlite3 /root/vpn_auth/vpn_users.db \
  "SELECT COUNT(*) FROM devices WHERE winn3_static_private IS NOT NULL"
```

The count must reach 0. Record the migration in `$RECOVERY_RECORD`.

### Step 8. Ship an app release that replaces g2 in the client ring

Clients trust exactly three slots, g1 to g3. Ship an app release whose
client ring drops g2 (g1 and g3 only), and raise `min_supported_version` so
every client runs it. After that, g2 signatures are unverifiable by clients
and the slot is fully retired.

## The v3 gap, and its arithmetic

v3 is unavailable on each node from step 1 until its step 5. With the
recovery allowance (design section 3.12), the gap is mainly the time to
prune keys, mint tickets and rebuild or rerun each node, which is hours for
the current fleet. For the six live nodes in `EVIDENCE_T3_LIVE.md`:

- Without the allowance and without a checkpoint, every rate-limit window
  starts as spent: 0 re-keys in the first 24 h, 4 at 24 h and 2 at 48 h, so
  the last two nodes stay off v3 for at least 48 h.
- Without the allowance, with a checkpoint and a clear window: 4 re-keys at
  once, and the other 2 after 24 h.
- With an allowance of 6: all six re-keys issue as soon as each node is
  pruned or rebuilt and ticketed, and a seventh is refused. After a
  reconciliation without a checkpoint that takes 12 tickets in all: one
  `unsuspend` and one `rekey` or `reset` per slug.

## The recovery record

`$RECOVERY_RECORD` is the operator-kept file for the incident. Record, per
slug: the containment time; the prune's printed fingerprints of every
remaining and removed line; every floor reset and its audit line; the
accepted residual for any in-place re-key; and every slug recorded as
`rebuild`. The record is the evidence that step 3 passed in allow-list mode
before any in-place re-key was allowed.
