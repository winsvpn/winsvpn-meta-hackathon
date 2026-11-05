#!/bin/sh
#
# AUDIT-CLOSE, controller side. Closes a retrieved evidence directory with the
# terminal winn-audit-checkpoint/v1 record, then verifies it with the real
# verifier.
#
# WHY THIS RUNS HERE AND NOT ON THE PRODUCING HOST.
#
# The checkpoint exists to constrain the party that writes the audit trail. On
# AICORE that party is winn-carrier-server, launched as root by the harness. A
# finalizer seed stored on that host would be readable by it whatever its
# permission bits said, and its environment readable whatever was scrubbed
# before exec: mode 0600 and `env -u` defend against a DIFFERENT, lesser
# identity, and are worth nothing against a party that already holds the same
# privilege as the credential's owner. A checkpoint signed by a key the audited
# process could read attests to nothing.
#
# So the seed exists only on the controller and finalization happens only on the
# controller, after the producing processes have stopped and the closed evidence
# has been copied back. AICORE and the controller are separate machines with no
# shared privilege domain, which is a boundary the carrier cannot cross no
# matter what it runs as. The producing runner runs
# `winn-audit -detect-finalizer-leaks` before it starts the writer, which
# catches the obvious ways that discipline gets broken — a seed copied into a
# deployment directory, an environment variable pointing at one. That scan is a
# secondary check and never proof of absence; the boundary is that the seed is
# never provisioned to that host at all.
#
# ORDER. The audit log was closed and fsynced by the producer, and the base
# evidence manifest was sealed by the producer, both before this runs. Only then
# is the checkpoint created, because it commits to the final hash of each. The
# base manifest excludes the checkpoint by construction — a manifest that hashed
# the checkpoint that hashed the manifest is a digest cycle — and the closed
# archive written at the end is the outer layer that commits to both together.
#
# Usage:
#   ./scripts/finalize_audit_checkpoint.sh AUDIT_BIN VERIFY_BIN EVIDENCE_DIR \
#       RUN_ID PRODUCER_DIGEST FINALIZER_SEED
#
# AUDIT_BIN        winn-audit, built on this controller
# VERIFY_BIN       winn-phase1-matrix-verify, built on this controller
# EVIDENCE_DIR     the retrieved evidence directory (closed log, sealed
#                  manifest). A checkpoint left by an interrupted previous run
#                  is verified and resumed from, not refused.
# RUN_ID           the run identity this evidence belongs to. For a matrix batch
#                  it is "<matrix_id>-<batch_key>", which is what the verifier
#                  re-derives per batch. For a standalone smoke it is the run
#                  root's name. It is supplied here, never read out of the
#                  checkpoint, because that is what makes a cross-run transplant
#                  detectable.
# PRODUCER_DIGEST  the reviewed source digest this evidence must bind. Supplied
#                  from outside for the same reason.
# FINALIZER_SEED   controller-only ML-DSA-65 seed, created once with
#                  `winn-audit -finalizer-keygen -finalizer-seed PATH`.

set -eu

if [ "$#" -ne 6 ]; then
	echo "usage: $0 AUDIT_BIN VERIFY_BIN EVIDENCE_DIR RUN_ID \
PRODUCER_DIGEST FINALIZER_SEED" >&2
	exit 64
fi

audit_bin=$1
verify_bin=$2
evidence_dir=$3
run_id=$4
producer_digest=$5
finalizer_seed=$6

for binary in "$audit_bin" "$verify_bin"; do
	if [ ! -x "$binary" ]; then
		echo "not executable: $binary" >&2
		exit 1
	fi
done

if [ ! -d "$evidence_dir" ]; then
	echo "evidence directory is not a directory: $evidence_dir" >&2
	exit 1
fi

if [ ! -f "$finalizer_seed" ]; then
	echo "finalizer seed is not a regular file: $finalizer_seed" >&2
	exit 1
fi

# The seed must not sit inside the evidence it closes: archived alongside it,
# anyone holding the archive could re-close a truncated copy.
seed_directory=$(cd "$(dirname "$finalizer_seed")" && pwd)
evidence_absolute=$(cd "$evidence_dir" && pwd)
case "$seed_directory/" in
"$evidence_absolute/"*)
	echo "the finalizer seed must live outside the evidence directory" >&2
	exit 1
	;;
esac

if [ "${#producer_digest}" -ne 64 ] ||
	! printf '%s' "$producer_digest" | grep -qE '^[0-9a-f]{64}$'; then
	echo "producer digest is not 64 lower-hex characters" >&2
	exit 1
fi

if [ -z "$run_id" ]; then
	echo "a run identity is required; it is never read from the checkpoint" >&2
	exit 1
fi

# --- preflight -------------------------------------------------------------
#
# Everything that can be checked is checked BEFORE the finalizer credential is
# used, because sealing is create-once: a checkpoint published over evidence
# that then turns out to be malformed, or into a directory whose archive already
# exists, cannot be withdrawn and cannot be redone. Spending the one-shot
# signing step on unvalidated data is the failure this ordering exists to
# prevent.

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	else
		shasum -a 256 "$1" | awk '{ print $1 }'
	fi
}

checkpoint_file="$evidence_dir/audit-checkpoint.json"

# The output path is NOT pre-refused here. An occupied destination holding the
# artifact this run would itself produce is a completed publication, and
# refusing it would turn an interrupted run into a permanently stuck one.
# internal/closedarchive makes that judgement: identical bytes are a success, a
# different artifact is a refusal, and a dangling symlink is caught with Lstat
# rather than missed by [ -e ].

# The base evidence has to be well formed before any of it is attested to.
for required in carrier-audit.jsonl evidence-manifest.sha256 environment.txt; do
	if [ ! -f "$evidence_dir/$required" ]; then
		echo "retrieved evidence lacks $required" >&2
		exit 1
	fi
done
if ! (cd "$evidence_dir" && sha256sum -c evidence-manifest.sha256 >/dev/null 2>&1) &&
	! (cd "$evidence_dir" && shasum -a 256 -c evidence-manifest.sha256 >/dev/null 2>&1); then
	echo "retrieved base manifest does not match the files it covers" >&2
	exit 1
fi

finalizer_key_id=$("$audit_bin" \
	-finalizer-key-id \
	-finalizer-seed "$finalizer_seed" |
	sed -n 's/.*"finalizer_key_id":"\([0-9a-f]*\)".*/\1/p')
if [ "${#finalizer_key_id}" -ne 64 ]; then
	echo "could not read the finalizer key identity" >&2
	exit 1
fi

# --- close -----------------------------------------------------------------
#
# Resume rather than refuse. A previous run may have published the checkpoint
# and then died before the archive existed; the checkpoint is create-once, so
# refusing outright would make that state unrecoverable. An existing checkpoint
# is therefore VERIFIED against the same external bindings this run was given,
# and the run continues only if it is the checkpoint this run would have made.
if [ -e "$checkpoint_file" ]; then
	echo "== an audit checkpoint already exists; verifying it before resuming =="
	if ! "$audit_bin" \
		-verify-checkpoint \
		-evidence-dir "$evidence_dir" \
		-audit-log-name carrier-audit.jsonl \
		-run-id "$run_id" \
		-producer-digest "$producer_digest" \
		-finalizer-key-id-pin "$finalizer_key_id"; then
		echo "the existing checkpoint does not match this run; refusing" >&2
		exit 1
	fi
else
	echo "== closing the retrieved audit trail =="
	"$audit_bin" \
		-seal-checkpoint \
		-evidence-dir "$evidence_dir" \
		-audit-log-name carrier-audit.jsonl \
		-manifest-name evidence-manifest.sha256 \
		-run-id "$run_id" \
		-producer-digest "$producer_digest" \
		-finalizer-seed "$finalizer_seed"
fi

echo
echo "== verifying the closed evidence with the real verifier =="
"$verify_bin" \
	-carrier-conservation-report "$evidence_dir" \
	-audit-finalizer-key-id "$finalizer_key_id" \
	-audit-run-id "$run_id" \
	-audit-producer-digest "$producer_digest"

# --- publish ---------------------------------------------------------------
#
# One atomic artifact, published by winn-audit rather than by this script.
#
# The shell version of this step was wrong in three ways shell cannot fix. It
# claimed to fsync the archive before publishing it and could not (POSIX sh has
# no fsync). It published the archive and its .sha256 pin with two separate
# link() calls, so a crash between them left the archive published without its
# pin — and because the next run refuses an occupied output path, that state was
# permanently stuck rather than retryable. And its existence checks used [ -e ],
# which is false for a dangling symlink, so a stale link from an earlier crash
# read as "absent".
#
# The fix that shapes the current design: publication is ONE file. There is no
# pin sidecar to fall out of step, because the digest is printed here and
# recorded by whatever binds it. See internal/closedarchive.
closed_archive="${evidence_dir%/}.closed.tar.gz"
publish_output=$("$audit_bin" \
	-publish-closed-archive \
	-evidence-dir "$evidence_dir" \
	-closed-archive "$closed_archive")
echo "$publish_output"
closed_digest=$(printf '%s' "$publish_output" |
	sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p')
if [ "${#closed_digest}" -ne 64 ]; then
	echo "could not read the closed archive digest" >&2
	exit 1
fi

echo
echo "EVIDENCE_DIR=$evidence_absolute"
echo "AUDIT_CHECKPOINT_RUN_ID=$run_id"
echo "AUDIT_FINALIZER_KEY_ID=$finalizer_key_id"
echo "CLOSED_ARCHIVE=$closed_archive"
echo "CLOSED_ARCHIVE_SHA256=$closed_digest"
