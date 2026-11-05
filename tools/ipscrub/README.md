# ipscrub — the pre-push disclosure gate

Refuses any `git push` that would **upload** a globally routable IP address
(v4 or v6) or WireGuard private/preshared key material to the remote.

## Install it — every fresh clone needs this

```sh
sh tools/ipscrub/install-hooks.sh
```

`.git/hooks/` is not version controlled. Committing these files is what makes
the gate **recoverable and reviewable**; that one command is what makes it
**live**. Until you run it, `git push` from your clone is unguarded — and the
gate's whole reason for existing is that nobody notices an unguarded push until
after it has happened.

Safe to re-run. If everything is current it changes nothing and says so. It
will not silently displace a `pre-push` hook it did not write: an unrelated hook
is backed up to `.git/hooks/pre-push.displaced-by-ipscrub.<timestamp>` and
announced.

## Files

| File | Role |
|---|---|
| `pre-push` | POSIX-sh wrapper. Fails closed on every error path. |
| `ipscrub.py` | The detector and the gate logic. Stdlib only, Python 3.8+. |
| `ipscrub-allowlist.txt` | 48 reviewed entries, each with its reason. |
| `install-hooks.sh` | Copies the three into `.git/hooks/`, then verifies. |

## What it scans — and why not everything

Only the objects the push would **newly upload**:

```
git rev-list --objects <pushed tip> --not <remote tip> --remotes=origin
```

That is the disclosure surface and nothing else. This repository's
already-pushed history is saturated with addresses that predate the gate, so a
whole-history gate would block **every push forever** — and a gate that refuses
everything gets switched off within a day. History already on the remote is a
server-side problem, not a pre-push one.

Remote-tracking refs are only as fresh as the last fetch, which errs toward
scanning *more* than necessary, never less.

## Why the hook is copied, and `core.hooksPath` is not set

`core.hooksPath` would keep the hook automatically fresh — that is a real
advantage and it is the failure this directory exists to prevent. It was still
rejected, for two reasons:

1. **It is exclusive.** It replaces `.git/hooks` wholesale, silently disabling
   every other hook a developer has, or installs later. That is the
   "clobber an unrelated hook" failure, generalised to hooks that do not exist
   yet and so cannot be warned about.
2. **It makes the gate branch-dependent.** Check out any branch that predates
   `tools/ipscrub/` — including `main` — and git finds no hook at all, so the
   push runs unguarded, with no message. A gate that vanishes on
   `git checkout main` is worse than one that goes stale.

Freshness is bought a different way instead. The installed `pre-push` is only a
launcher. The logic that actually changes — `ipscrub.py` and the allowlist — is
resolved **from the working tree first**, so a `git pull` that improves the
detector takes effect on the next push with no reinstall. The copies beside the
hook are the fallback that keeps the gate alive on branches where the tracked
copy is absent. **Trigger pinned, logic fresh.** The hook prints which copy it
used, so this is never ambiguous.

## Using it directly

```sh
# What would pushing this branch upload?
python3 tools/ipscrub/ipscrub.py prepush-preview --ref <branch>

# Working tree only
python3 tools/ipscrub/ipscrub.py scan

# Prove the detector still works (184 cases, both directions)
python3 tools/ipscrub/ipscrub.py \
    --allowlist tools/ipscrub/ipscrub-allowlist.txt selftest

# Is the packed scan armed in this checkout, and from where?
python3 tools/ipscrub/ipscrub.py node-map-status
```

Binary blobs are read too, not skipped. A blob on an evidence path is refused
outright; anywhere else its printable runs (ASCII and UTF-16LE) go through the
same detector the text path uses.

`--allowlist` defaults to the file next to `ipscrub.py`, so it is only needed
when you want a different one.

## The packed scan, and how to arm it

Packed 4/16-byte addresses are searched for **only** against a node map you
supply out of band, because any four bytes are a valid IPv4 address and an
unguided packed scan is pure noise. Until 2026-08-07 nothing supplied one
anywhere, so that path was off in every checkout and every scan still printed
`clean` — dead code reporting success. Two things changed:

1. **Every run now says which state it is in**, ON or OFF, on stderr. You
   cannot get a green result any more without being told what it covered.
2. **A node map is wired per clone**, with one command:

```sh
git config ipscrub.nodeMap /path/outside/this/repo/node-map.txt
```

`.git/config` is not version controlled and is never pushed, so the *path* is
local state and the *file* stays where it belongs — the no-remote archive at
`~/Documents/wins/docs` already holds one. `--node-map PATH` and
`$IPSCRUB_NODE_MAP` still work and take precedence, in that order.

Three things are now hard errors rather than a quiet partial scan: a node map
**inside this repository** (that file is precisely what the gate keeps out), a
configured path that **does not exist**, and a map that parses to **nothing**.
Add `--require-node-map` (or `$IPSCRUB_REQUIRE_NODE_MAP=1`) wherever a green
result is supposed to *mean* the packed scan ran.

### Why this is not in CI

It was considered and rejected, and not on style:

- The map is the list of addresses whose disclosure to GitHub this gate exists
  to prevent. An Actions secret hands that exact list to GitHub to hold.
- **CI runs after the push.** By the time a workflow starts, the objects are
  already on the remote; a packed scan there is forensics, not a gate. The
  pre-push hook is the only place where the answer still changes the outcome.
- Anyone who can land a workflow change can read a secret, and this remote's
  visibility, forks, collaborators and deploy keys have not been checked.

Running it off this machine would need a runner on operator-controlled hardware
reading the map from local disk, with no third party ever holding the file.
Nothing in the current setup provides that, and no substitute was invented.

## If it blocks you

Replace the literal with the project placeholders — `<KANSAS_IP>`,
`<NODE_ES_IP>`, `<OPERATOR_WAN>` — and push again.

A redaction commit layered **on top** does not help. The original blob is still
reachable from the tip you are pushing, so it still uploads, and the gate still
sees it. You have to rewrite, not append.

If a value is genuinely publishable — a provider's published range, a public
resolver — add it to `tools/ipscrub/ipscrub-allowlist.txt` **with a reason**.
Edit the tracked copy, not the one in `.git/hooks/`; editing that one helps you
once and nobody else ever. **Never allowlist one of this project's own node
addresses.**

## False positives are handled by rule, not by holes

Version quads, bare library versions, ASN.1 OIDs and route-math CIDR bases are
suppressed **structurally**, so the allowlist does not grow a hole every time a
new one appears. Each rule is bounded so it cannot reach a node address:

- The version and library rules require **no letters** between the keyword and
  the quad, so `node <addr>` and `the CUDA box at <addr>` are still flagged.
  `node` is deliberately not a library keyword.
- The OID rule requires a **root arc ≤ 2** (X.660), so no address whose first
  octet is 3 or more can be suppressed by it, whatever words share its line.
- The route-prefix rule requires a prefix shorter than /8 (v4) or /16 (v6)
  **and** that the literal be exactly the block base — every host bit zero. A
  node address is not the base of a `/3`.

Every suppression is counted, and listable with `--show-suppressed`. A rule can
never quietly hide an address.

## Limits — read these

- It does not police what is **already on the remote**. That is addressable
  only server-side.
- It does not stop `IPSCRUB_ALLOW_PUSH=1`. That override exists precisely
  because it has to be typed deliberately.
- WireGuard **public** keys warn but do not block. A public key is public by
  construction; what makes it disclosive is being tabulated next to a node
  address, and the address is what the gate already blocks.
- **It only protects checkouts where `install-hooks.sh` has been run.**
- In a **binary**, an address welded to a word with no delimiter on either side
  (`wg01.2.3.4`) is deliberately ignored. That rule is what keeps Go closure
  symbols like `...marshal.func1.1.1.1` from producing 96 false alarms per
  push; no real serializer emits an address that way.
- Without a node map, an address present in a binary **only** in packed form
  and never as text is not found. There is no way to fix this by heuristic — a
  structural `sockaddr_in` rule was tried and produced 840 false hits across 33
  files, including image assets. See the measurement in `ipscrub.py` under
  *PACKED SCANNING*, and the three self-test cases that fail if anyone re-adds
  it in any of its three serialisations.
- It does not police **already-published history**, and a `.pcap` cannot be
  scrubbed at all: the addresses sit in IP headers under checksums, so for
  captures the only mechanism is removal, server-side.

## Provenance

Ported from `wins/docs` → `tools/ipscrub/` (2026-08-06), with scope changed to
the push delta, plus IPv6, WireGuard key shapes and two further false-positive
shapes. See `docs/handoff/PREPUSH_GATE_AND_DISCLOSURE_SCRUB_WINS_VPN_20260807.md`
for the calibration evidence, and the dated handoff beside it for this
relocation.
