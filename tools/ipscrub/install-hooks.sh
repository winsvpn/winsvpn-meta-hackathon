#!/bin/sh
# Install the ipscrub pre-push disclosure gate into this checkout.
#
# One command, from anywhere inside the repository:
#
#     sh tools/ipscrub/install-hooks.sh
#
# RUN THIS AFTER EVERY FRESH CLONE. .git/hooks/ is not version controlled, so
# the gate does NOT travel with the repository. Committing the source under
# tools/ipscrub/ is what makes it recoverable and reviewable; this script is
# what makes it live in a given checkout. Until it runs, `git push` from this
# clone is unguarded.
#
# Safe to run repeatedly: if everything is already current it changes nothing
# and says so. It will not silently displace a pre-push hook it did not write.

set -eu

BAR='------------------------------------------------------------------------'

SELFDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(git -C "$SELFDIR" rev-parse --show-toplevel)
SRC="$ROOT/tools/ipscrub"

FILES='pre-push ipscrub.py ipscrub-allowlist.txt'

for f in $FILES; do
    [ -f "$SRC/$f" ] || { echo "install-hooks: missing $SRC/$f" >&2; exit 1; }
done

# `--git-path hooks` already honours core.hooksPath, so this is the directory
# git will really consult. If somebody has redirected it, installing into
# .git/hooks/ would be a no-op that LOOKS like success -- which is the exact
# class of failure this gate exists to avoid. Say it out loud.
HOOKS=$(git -C "$ROOT" rev-parse --git-path hooks)
case "$HOOKS" in /*) ;; *) HOOKS="$ROOT/$HOOKS" ;; esac

CONFIGURED=$(git -C "$ROOT" config --get core.hooksPath || true)
if [ -n "$CONFIGURED" ]; then
    echo "$BAR"
    echo "install-hooks: NOTE -- core.hooksPath is set to:"
    echo "                   $CONFIGURED"
    echo "               so git reads hooks from there, NOT from .git/hooks."
    echo "               Installing into the directory git actually uses:"
    echo "                   $HOOKS"
    echo "$BAR"
fi

mkdir -p "$HOOKS"

# ---------------------------------------------------------------------------
# pre-push: never displace a hook we did not write without saying so.
# ---------------------------------------------------------------------------
DST="$HOOKS/pre-push"
changed=0

if [ -e "$DST" ] && cmp -s "$SRC/pre-push" "$DST"; then
    echo "install-hooks: pre-push already current -- unchanged."
else
    if [ -e "$DST" ]; then
        if grep -q 'ipscrub pre-push gate' "$DST" 2>/dev/null; then
            echo "install-hooks: replacing an older ipscrub pre-push hook."
        else
            BACKUP="$DST.displaced-by-ipscrub.$(date +%Y%m%d%H%M%S)"
            cp -p "$DST" "$BACKUP"
            echo "$BAR"
            echo "install-hooks: WARNING -- an EXISTING, NON-ipscrub pre-push hook was"
            echo "               found and has been displaced. It was NOT discarded:"
            echo "                   $BACKUP"
            echo "               If you need both, restore yours and invoke ours from"
            echo "               it, forwarding stdin and preserving the exit status:"
            echo "                   \"\$(git rev-parse --show-toplevel)\"/tools/ipscrub/pre-push \"\$@\" || exit 1"
            echo "$BAR"
        fi
    fi
    cp "$SRC/pre-push" "$DST"
    echo "install-hooks: installed $DST"
    changed=1
fi
chmod +x "$DST"

# ---------------------------------------------------------------------------
# Scanner + allowlist: the FALLBACK pair beside the hook.
#
# The wrapper prefers $ROOT/tools/ipscrub at run time so the detector stays
# fresh with `git pull`. These copies are what keep the gate alive on a branch
# checked out from before tools/ipscrub existed, where the tracked copy is
# simply absent from the working tree.
# ---------------------------------------------------------------------------
for f in ipscrub.py ipscrub-allowlist.txt; do
    if [ -e "$HOOKS/$f" ] && cmp -s "$SRC/$f" "$HOOKS/$f"; then
        echo "install-hooks: $f fallback already current -- unchanged."
    else
        cp "$SRC/$f" "$HOOKS/$f"
        chmod 0644 "$HOOKS/$f"
        echo "install-hooks: installed fallback $HOOKS/$f"
        changed=1
    fi
done

[ "$changed" -eq 0 ] && echo "install-hooks: nothing to do, the gate was already installed."

# ---------------------------------------------------------------------------
# Verify. An installer that prints 'done' without proving the gate runs is the
# same failure mode as a hook that opens when it breaks.
#
# 2026-08-07: this section used to verify $SRC -- the TRACKED copy -- and then
# report success. That is the wrong file. It meant the installer could print
# "detector self-test PASSED" and "gate is LIVE" while the copy it had just
# installed beside the hook was stale, because nothing ever executed the
# installed copy. It happened: ipscrub.py was repaired at 04:58 and the
# fallback in .git/hooks sat at 01:44, three markers of the fix absent from it,
# and every install run in between said everything was fine.
#
# So verification now runs against the INSTALLED files, and digests are
# compared explicitly. Verifying the source proves only that the source is
# good, which was never in doubt.
# ---------------------------------------------------------------------------
echo "install-hooks: verifying..."

# Digest comparison first: cheap, and it catches a partial or failed copy that
# a self-test on either file could still pass.
if command -v shasum >/dev/null 2>&1; then
    SUM='shasum -a 256'
elif command -v sha256sum >/dev/null 2>&1; then
    SUM='sha256sum'
else
    SUM=''
fi

if [ -n "$SUM" ]; then
    drift=0
    for f in pre-push ipscrub.py ipscrub-allowlist.txt; do
        a=$($SUM "$SRC/$f" | cut -d' ' -f1)
        b=$($SUM "$HOOKS/$f" | cut -d' ' -f1)
        if [ "$a" != "$b" ]; then
            echo "install-hooks: FAILED -- $f differs from the tracked copy AFTER" >&2
            echo "                 installing it. tracked:   $a" >&2
            echo "                 installed: $b" >&2
            drift=1
        fi
    done
    if [ "$drift" -ne 0 ]; then
        echo "install-hooks: the installed gate is NOT the tracked gate. Refusing" >&2
        echo "               to report success." >&2
        exit 1
    fi
    echo "install-hooks: installed copies are digest-identical to the tracked ones."
else
    echo "install-hooks: WARNING -- no shasum/sha256sum, cannot digest-compare." >&2
fi

PY=""
for candidate in python3 /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PY=$(command -v "$candidate"); break; fi
done
if [ -z "$PY" ]; then
    echo "install-hooks: FAILED -- no python3 found. The hook is installed but" >&2
    echo "               will fail closed on every push until python3 exists." >&2
    exit 1
fi

# The INSTALLED copy, not the source. This is the fallback that runs on any
# branch predating tools/ipscrub, and it is the copy that went stale unnoticed.
if "$PY" "$HOOKS/ipscrub.py" --allowlist "$HOOKS/ipscrub-allowlist.txt" selftest \
        >/dev/null 2>&1; then
    echo "install-hooks: detector self-test PASSED (running the INSTALLED copy)."
else
    echo "install-hooks: FAILED -- the detector self-test did not pass when run" >&2
    echo "               against the INSTALLED copy at:" >&2
    echo "                   $HOOKS/ipscrub.py" >&2
    echo "               The gate is installed but must not be trusted. Run:" >&2
    echo "                   python3 tools/ipscrub/ipscrub.py \\" >&2
    echo "                       --allowlist tools/ipscrub/ipscrub-allowlist.txt selftest" >&2
    exit 1
fi

# Drive the installed hook exactly the way git does. NOTE which copy this
# exercises: the wrapper prefers $ROOT/tools/ipscrub, so on a checkout that has
# the tracked tree -- like this one -- the probe below runs the TRACKED
# scanner, not the fallback just installed. The fallback is what the self-test
# above and the digest comparison cover; between them all three files are
# verified. The wrapper prints which copy it chose, and that line is shown.
#
# Drive it the way git does: one ref line on stdin,
# `<local ref> <local sha> <remote ref> <remote sha>`, with an all-zero remote
# sha meaning "this push would CREATE the ref", which is the widest delta.
HEADSHA=$(git -C "$ROOT" rev-parse HEAD)
ZERO=0000000000000000000000000000000000000000
if printf 'refs/heads/probe %s refs/heads/probe %s\n' "$HEADSHA" "$ZERO" \
       | "$DST" origin "ipscrub://install-probe" >/dev/null 2>&1; then
    echo "install-hooks: gate is LIVE and reports CLEAN for HEAD."
else
    echo "install-hooks: gate is LIVE and reports BLOCKING for HEAD."
    echo "               That is the protection working, not an install error."
    echo "               To see what it found:"
    echo "                   python3 tools/ipscrub/ipscrub.py \\"
    echo "                       --allowlist tools/ipscrub/ipscrub-allowlist.txt \\"
    echo "                       prepush-preview --ref HEAD"
fi

# ---------------------------------------------------------------------------
# The packed scan, and the state it is actually in.
#
# 2026-08-07: the packed-value scan -- the one that finds an address stored as
# raw 4/16 bytes rather than as text -- runs only when a node map is supplied
# out of band, and NOTHING supplied one. It was off in every checkout and in
# every job, and every scan still printed "clean". That is dead code reporting
# success, which is the same defect this installer was rebuilt to catch in the
# hook itself.
#
# It is not fixed by putting the map in CI. The map is the list of addresses
# whose disclosure to GitHub this gate exists to prevent, and CI runs after the
# push has already happened. The pre-push path is the only place where knowing
# is still worth anything, and `git config` is the only per-clone store that is
# local, survives a reboot, and is never pushed. So: report the state here, and
# print the one command that arms it.
# ---------------------------------------------------------------------------
if "$PY" "$SRC/ipscrub.py" node-map-status --repo "$ROOT"; then
    echo "install-hooks: the packed scan is armed in this checkout."
else
    echo "$BAR"
    echo "install-hooks: the packed scan is OFF here. That is not an install"
    echo "               error and it does not weaken the text scan -- but a"
    echo "               'clean' result does NOT cover addresses that exist in a"
    echo "               binary only as raw bytes. To arm it, once per clone:"
    echo ""
    echo "                   git config ipscrub.nodeMap <path OUTSIDE this repo>"
    echo ""
    echo "               The no-remote archive at ~/Documents/wins/docs already"
    echo "               holds a node map. Point at it there. NEVER copy it into"
    echo "               this repository -- a path inside the tree is refused,"
    echo "               because that file is exactly what the gate keeps out."
    echo "$BAR"
fi

echo "install-hooks: done."
