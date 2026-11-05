#!/bin/sh
# check_flip_authorization.sh <full-target-sha> <lane>
# Fail-closed guard for the separate-artifact flip (Opus binding ruling +
# S1-S5 + F1-F3). Read-only. Exit 0 PASS, exit 1 with reason on any failure.
# REPO_DIR override exists only to test the guard against tampered copies.
set -u
REPO="${REPO_DIR:-/Users/owner/xprize/winsvpnv3}"
TARGET="${1:?usage: check_flip_authorization.sh <full-target-sha> <lane>}"
LANE="${2:?usage: check_flip_authorization.sh <full-target-sha> <lane>}"
fail() { echo "GUARD-REFUSE: $1"; exit 1; }

case "$TARGET" in *[!0-9a-f]*|"") fail "target SHA not full hex" ;; esac
[ "${#TARGET}" -eq 40 ] || [ "${#TARGET}" -eq 64 ] || fail "target SHA bad length"
FLIP="$REPO/deploy/production-input-evidence/FLIP-AUTHORIZATION-$TARGET.json"
[ -f "$FLIP" ] || fail "exact FLIP path missing: $FLIP"
[ ! -L "$FLIP" ] || fail "FLIP path is a symlink"
[ "$(echo "$FLIP" | tr -cd '/' | wc -c)" -ge 1 ] || fail "noncanonical path"
case "$FLIP" in *".."*|"//"*) fail "noncanonical path" ;; esac

HEAD="$(git -C "$REPO" rev-parse HEAD 2>/dev/null)" || fail "HEAD unreadable"
[ -z "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] || fail "dirty tree"
UTC_NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" || fail "no trusted UTC"
case "$UTC_NOW" in ????-??-??T??:??:??Z) : ;; *) fail "clock unparseable" ;; esac

export FLIP TARGET HEAD UTC_NOW LANE REPO
python3 - << 'PYEOF' || exit 1
import json, os, subprocess, hashlib

repo = os.environ["REPO"]
flip_path = "deploy/production-input-evidence/FLIP-AUTHORIZATION-%s.json" % os.environ["TARGET"]
full = open(os.path.join(repo, flip_path), "rb").read()

def fail(msg):
    print("GUARD-REFUSE: " + msg)
    raise SystemExit(1)

# strict JSON: no duplicate keys, exact known fields (S1)
ALLOWED = {"schema_version","approved_sha","approved_sha_full","baseline_sha","baseline_sha_full",
 "scope","basis","expires_at","authorized_at_utc","authority","pin_channel","self_disclosure",
 "evidence_pins","owner_inputs","delta_justification","analyst_positions","arbiter_ruling","signer"}
def hook(pairs):
    # duplicate detection at every level; field whitelist checked above
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        fail("duplicate JSON keys")
    return dict(pairs)
try:
    top = json.loads(full.decode())
except Exception as exc:
    fail("FLIP JSON invalid: " + type(exc).__name__)
for k in top.keys():
    if k not in ALLOWED:
        fail("unknown field " + k)
def hook(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        fail("duplicate JSON keys")
    return dict(pairs)
try:
    d = json.loads(full.decode(), object_pairs_hook=hook)
except SystemExit:
    raise
except Exception as exc:
    fail("FLIP JSON invalid: " + type(exc).__name__)

# filename SHA binds approved SHA (S1 strict + F3 prefix test)
if d.get("approved_sha_full") != os.environ["TARGET"]:
    fail("approved_sha_full != target SHA")
if not d.get("approved_sha") or not os.environ["TARGET"].startswith(d["approved_sha"]):
    fail("filename SHA prefix mismatch")

# git-tracked at ancestor-or-equal of HEAD; blob pin (amendment 2, S3)
def git(*a):
    return subprocess.run(["git","-C",repo]+list(a),capture_output=True,text=True)
r = git("log","--format=%H","-1","--",flip_path)
last = r.stdout.strip()
if not last:
    fail("FLIP file untracked")
if git("merge-base","--is-ancestor",last,os.environ["HEAD"]).returncode != 0:
    fail("FLIP commit not ancestor-or-equal of HEAD")
work_blob = git("hash-object",flip_path).stdout.strip()
if git("rev-parse","HEAD:"+flip_path).stdout.strip() != work_blob:
    fail("FLIP worktree bytes != committed bytes")

# out-of-band pin readable and matching (F1/CP1)
brief = open(os.path.join(repo,"docs/blueprints/AI_HANDOFF_20260823.md")).read()
if work_blob not in brief or os.environ["TARGET"] not in brief:
    fail("lane-brief pin absent or unreadable")

# approved vs HEAD: equal, or ancestor with zero product drift (arbiter SHA logic)
head = os.environ["HEAD"]
if head != os.environ["TARGET"]:
    if git("merge-base","--is-ancestor",os.environ["TARGET"],head).returncode != 0:
        fail("approved SHA not ancestor-or-equal of HEAD")
    roots = ["apps","core","crates","go","xcode","linux","windows","android"]
    if git("diff","--quiet",os.environ["TARGET"],head,"--",*roots).returncode != 0:
        fail("product drift between approved SHA and HEAD")

# clock vs expiry (amendment 5)
if not (os.environ["UTC_NOW"] < d.get("expires_at","")):
    fail("expired or unparseable expiry")

# lane in declared scope
lane = os.environ["LANE"]
if lane not in ("hub","dataplanes","aicore-core"):
    fail("unknown lane " + lane)
if lane not in json.dumps(d.get("scope",{})):
    fail("lane outside declared scope")

# evidence pins: worktree bytes AND committed bytes vs pinned values (S3/F2)
for pin in d.get("evidence_pins",[]):
    p = os.path.join(repo,pin["path"])
    if not os.path.isfile(p) or os.path.islink(p):
        fail("evidence missing: " + pin["path"])
    raw = open(p,"rb").read()
    if len(raw) != pin["byte_length"]:
        fail("byte length mismatch: " + pin["path"])
    if hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        fail("sha256 mismatch: " + pin["path"])
    r = git("rev-parse","HEAD:"+pin["path"])
    if r.returncode != 0 or r.stdout.strip() != pin["repo_blob"]:
        fail("committed blob mismatch: " + pin["path"])
    r = git("hash-object",pin["path"])
    if r.stdout.strip() != pin["repo_blob"]:
        fail("worktree blob mismatch: " + pin["path"])

print("GUARD-PASS head=%s target=%s lane=%s" % (head[:12], os.environ["TARGET"][:12], lane))
PYEOF

# manifest validates clean with authorized=false (template invariant)
OUT="$(python3 "$REPO/tools/deployment_owner_inputs.py" validate "$REPO/deploy/production-input-evidence/PENDING-OWNER-INPUT.json" 2>&1)" || fail "validator refused: $OUT"
case "$OUT" in *"deployment_authorized=false"*) : ;; *) fail "manifest not in blank state: $OUT" ;; esac
echo "GUARD-PASS manifest blank-state confirmed"
