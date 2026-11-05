# rclone Custom Google OAuth Client Migration Plan

Last updated: 2026-07-23

## Status: steps 1-4 complete and verified

The dedicated OAuth client has been created and is live in the local rclone
config. `rclone about gdrive-admin-winsvpn-org:` returns real account data
(15 GiB) with **no shared-client retirement warning** -- confirming the
remote is genuinely running on the dedicated client, not the shared one.

What was done:

- Google Cloud project `wins-vpn-rclone-backup` created under admin@winsvpn.org.
- Google Drive API enabled.
- OAuth consent screen configured. Confirmed empirically (not assumed) that
  `winsvpn.org` is **not** a Google Workspace domain -- the "Internal" audience
  option was greyed out/unselectable in Google's own UI, leaving External +
  Testing as the only available (and correct, per this plan) choice.
- `admin@winsvpn.org` added as a test user (a separate step from the OAuth
  consent screen's "support email" field -- the first authorization attempt
  failed with `Error 403: access_denied` until this was done specifically).
- Dedicated OAuth client created, type Desktop app, name
  `wins-vpn-rclone-backup`, client ID
  `<GOOGLE_OAUTH_CLIENT_ID>.apps.googleusercontent.com`.
- A fresh token minted via `rclone authorize "drive" <id> <secret>`, bound to
  this client (consent screen correctly showed "Wins VPN rclone Backup", not
  generic "rclone" -- confirms the right client was used).
- Local `~/.config/rclone/rclone.conf` remote `[gdrive-admin-winsvpn-org]`
  updated with the dedicated client's `client_id`/`client_secret`/`token`.
  The original Google-issued credential JSON is preserved at
  `~/.config/rclone/oauth_client_wins_vpn_rclone_backup.json` (mode 600,
  outside the git repo).

**One incident during this work, resolved:** the credentials JSON was briefly
downloaded into the `wins_vpn` repository root (an artifact of the browser
used to fetch it) -- untracked and not yet committed, but not gitignored
either, so a broad `git add` would have swept it in. Caught immediately,
moved to `~/.config/rclone/` outside the repo. Confirmed via
`git log --all --diff-filter=A --name-only | grep client_secret` (empty
result) that the file was never committed to any branch at any point --
not just currently absent, but never present in history at all.

Remaining: steps 5 (crypt wrapper) and 6 (deploy at reset time + revoke old
shared-client grant) below, unchanged from the original plan.

## Original Recommendation

Replace rclone's shared/default Google Drive OAuth client with a dedicated
Google Cloud OAuth client registered under this project, before rclone's
shared client is retired (rclone itself now warns this is happening "during
2026" -- check `rclone about <remote>:` output for the current wording and
timeline, since this plan does not hardcode an exact retirement date).

## Why This Matters

`rclone authorize`/`rclone config` will mint a working Google Drive token
with no extra setup by using rclone's own shared, globally-registered OAuth
client. That is convenient but has two problems for a production backup
credential:

- It is being retired. Once Google/rclone cut it over, tokens minted against
  it stop working and every remote using it needs re-authorization anyway --
  better to do that migration deliberately now than as an unplanned outage.
- It is opaque for auditing/revocation. In the Google Account "Linked apps"
  UI, every rclone user's grant (including this project's) shows up as the
  same generic "rclone" entry. There is no way to see or revoke just this
  project's access without affecting every other token issued to that shared
  client identity -- which is exactly the limitation hit while rotating the
  Google Drive credential on 2026-07-23 (see `docs/CREDENTIAL_ROTATION_AND_HISTORY_PURGE_20260713.md`
  item 2). A dedicated client shows up under this project's own Google Cloud
  project, separate from anyone else's rclone usage, and can be individually
  disabled or have its secret rotated from Cloud Console without touching
  anything else.

## Current State (as of this plan)

- `~/.config/rclone/rclone.conf` on the primary Mac has one remote,
  `[gdrive-admin-winsvpn-org]`, authorized against `admin@winsvpn.org` using
  rclone's shared client. This is a local, not-yet-deployed credential --
  the control hub and data plane are being reset, so nothing has been pushed
  to a live server yet.
- The old (possibly-exposed) Google Drive credential is still live on the
  current production hub. It was not revoked during the 2026-07-23 rotation
  because revoking it would also kill the new one (same shared-client
  limitation described above) and break the still-running production backup
  job ahead of schedule.
- The `[GoogleDrive_secured]` crypt wrapper (client-side encryption around
  the raw Drive remote -- see `rclone_crypt_remote_contract()` in
  `server/wins_control_plane_setup_ONETOUCH.sh`) has not been created yet.
  It needs its own `password`/`password2` pair, which is a separate secret
  from anything in this plan.

## Procedure

### 1. Create a dedicated Google Cloud OAuth client

1. Go to <https://console.cloud.google.com>, signed in as `admin@winsvpn.org`.
2. Create a new project (or pick an existing one already used only for this
   purpose -- do not attach this to an unrelated project).
3. APIs & Services -> Library: enable the **Google Drive API**.
4. APIs & Services -> OAuth consent screen:
   - If `winsvpn.org` is a Google Workspace domain, choose **Internal** --
     this skips Google's public verification review entirely since only
     accounts on this domain can use it.
   - If it is a plain consumer/Gmail-hosted domain, choose **External** and
     leave the app in **Testing** mode with `admin@winsvpn.org` added as a
     test user. Testing-mode apps do not need Google's review and do not
     expire the way some assumptions about "unverified apps" suggest, as
     long as the requested scope stays a non-sensitive/standard Drive scope.
5. APIs & Services -> Credentials -> Create Credentials -> OAuth client ID:
   - Application type: **Desktop app** (this matches how `rclone authorize`
     drives a local-redirect flow; do not use "Web application").
   - Name it something identifiable, e.g. `wins-vpn-rclone-backup`.
6. Save the resulting **Client ID** and **Client Secret** somewhere that
   gets the same handling as any other credential in this project -- not in
   any git-tracked file. A local root-owned file or a password manager entry
   is fine; `.env.example`-style tracked files must keep using placeholders,
   per `SECURITY_NOTES_FINAL.md`.

### 2. Mint a token bound to the new client

```bash
rclone authorize "drive" "<CLIENT_ID>" "<CLIENT_SECRET>"
```

This opens the same browser consent flow as before, but the consent screen
will now show the app name chosen in step 1.5 instead of generic "rclone" --
confirm that before approving, as a sanity check that the right client is
being used.

### 3. Update the local remote

Add `client_id` and `client_secret` to the existing raw Drive remote so the
token is no longer tied to the shared client:

```ini
[gdrive-admin-winsvpn-org]
type = drive
scope = drive
client_id = <CLIENT_ID>
client_secret = <CLIENT_SECRET>
token = <the JSON blob rclone authorize just printed>
```

### 4. Verify

```bash
rclone about gdrive-admin-winsvpn-org:
```

Confirm this returns real account storage numbers and, importantly, that
the shared-client retirement warning is gone from the output.

### 5. Wrap in the crypt remote

Not covered by this plan (separate secret/decision -- see "Current State"
above). Once a `password`/`password2` pair exists, add the
`[GoogleDrive_secured]` crypt remote wrapping `gdrive-admin-winsvpn-org:`,
matching the shape `rclone_crypt_remote_contract()` in
`server/wins_control_plane_setup_ONETOUCH.sh` validates: `type = crypt`,
`remote = gdrive-admin-winsvpn-org:`, `filename_encryption = standard`,
`directory_name_encryption = true`, `no_data_encryption = false`.

### 6. Deploy at reset time

When the control hub is reset, inject the finished config through the
existing, already-correct contract -- no script changes needed:

- `RCLONE_CONFIG_SOURCE=/path/to/rclone.conf` (root-owned, mode `600`), or
- `RCLONE_CONFIG_B64=<base64 of the same file>` (under the 2 MiB limit
  `validate_rclone_injection_contract()` enforces)

Only then, with production confirmed running on the new dedicated-client
credential, revoke the old shared-client grant in
`myaccount.google.com` -> Security -> "Third-party apps & services" ->
rclone -> Remove access. Revoking earlier would kill the credential this
plan just built too, since both currently share the same generic client
identity.

## Operational Notes

- Treat the Client Secret from step 1 with the same rigor as `ADMIN_TOKEN`
  or any rclone token: root-owned, mode `600`, never committed.
- The Drive scope requested here (`drive`, i.e. full read/write) matches
  what the current backup setup already uses. Narrowing to `drive.file`
  (access limited to files the app itself created) is a reasonable future
  hardening step but is out of scope for this migration -- don't bundle it
  in without deciding it deliberately, since it changes what the backup
  script can see/restore.
- Do this migration before the shared-client retirement lands, ideally
  alongside the planned control-hub/data-plane reset so there is only one
  cutover event instead of two.
