#!/bin/sh
#
# Run the forced-abort carrier conservation smoke on AICORE, verify the sealed
# audit trail's HMAC chain with the real audit verifier, and only then judge the
# evidence with the real matrix verifier.
#
# This is Codex's gate-order step 4: force every closed abort reason through
# the real H3Server/H2Server handlers, alongside genuinely successful requests
# on both carriers, and prove exact conservation from the sealed evidence
# rather than from the harness's own arithmetic.
#
# BINDING. The runner, not the smoke, decides which artifact is allowed to
# produce evidence, and every part of that decision is mandatory:
#
#   * the reviewed artifact digest is a required argument. The runner hashes
#     the binary on disk, refuses to start unless it matches, and passes the
#     value in; the smoke refuses to run unless the executable it is actually
#     running hashes to the same value.
#   * the reviewed source digest is a required argument. The runner hashes the
#     deployed .source.sha256 manifest, refuses to start unless it matches, and
#     passes the value in; the smoke refuses to create any evidence at all
#     unless its own ldflags-stamped source digest equals it.
#
# Both digests are sealed into environment.txt, so the evidence names the
# artifact and the source tree that produced it.
#
# ORDER. The audit HMAC chain is verified before the conservation report runs.
# The report recomputes the conservation law from the sealed trail, which is
# only meaningful if the trail is authentic; checking authenticity afterwards
# would mean a tampered trail had already been reported as conserving. The
# audit key lives in the run root's work directory, deliberately outside the
# sealed evidence directory, so sealed evidence never carries the key that
# authenticates it.
#
# The smoke needs no privileged networking: it drives real anonymous-token
# CONNECT requests over loopback QUIC and TCP. It never touches an existing
# evidence root; the run directory it creates must not already exist.
#
# AUDIT-CLOSE. The smoke writes the audit trail, so the smoke's host must not be
# able to close it. On this host the smoke runs with the same identity that
# would own any local finalizer seed, so file modes and a scrubbed environment
# would protect nothing — the audited party could simply read the credential.
# The finalizer seed therefore lives ONLY on the controller, and the checkpoint
# is created there, over the retrieved evidence, by
# scripts/finalize_audit_checkpoint.sh. This runner proves the absence rather
# than assuming it: winn-audit -detect-finalizer-leaks refuses to let the smoke
# start if the obvious leak shapes are found here. That scan is a secondary
# check, not the boundary — the boundary is that the seed is never provisioned
# to this host at all.
#
# Usage:
#   ./scripts/aicore_conservation_smoke.sh SMOKE_BIN VERIFY_BIN AUDIT_BIN \
#       RUN_ROOT EXPECTED_SMOKE_SHA256 SOURCE_MANIFEST EXPECTED_SOURCE_DIGEST
#
# SMOKE_BIN              winn-phase1-conservation-smoke
# VERIFY_BIN             winn-phase1-matrix-verify
# AUDIT_BIN              winn-audit
# RUN_ROOT               new directory to create; evidence/ and work/ go inside
# EXPECTED_SMOKE_SHA256  required: the artifact digest the deployer reviewed
# SOURCE_MANIFEST        required: the deployed
#                        winn-phase1-conservation-smoke.source.sha256
# EXPECTED_SOURCE_DIGEST required: the SHA-256 of that manifest file, as
#                        printed by scripts/build_conservation_smoke_linux.sh
#
# The evidence this produces is CLOSED-PENDING: its trail is final and its
# manifest is sealed, but it carries no checkpoint and therefore cannot be
# accepted by the verifier until the controller closes it.

set -eu

if [ "$#" -ne 7 ]; then
	echo "usage: $0 SMOKE_BIN VERIFY_BIN AUDIT_BIN RUN_ROOT \
EXPECTED_SMOKE_SHA256 SOURCE_MANIFEST EXPECTED_SOURCE_DIGEST" >&2
	exit 64
fi

smoke_bin=$1
verify_bin=$2
audit_bin=$3
run_root=$4
expected_smoke_sha256=$5
source_manifest=$6
expected_source_digest=$7

for binary in "$smoke_bin" "$verify_bin" "$audit_bin"; do
	if [ ! -x "$binary" ]; then
		echo "not executable: $binary" >&2
		exit 1
	fi
done

if [ ! -f "$source_manifest" ]; then
	echo "source manifest is not a regular file: $source_manifest" >&2
	exit 1
fi

if [ -e "$run_root" ]; then
	echo "run root already exists, refusing to touch it: $run_root" >&2
	exit 1
fi

# Both expectations must be well formed before anything is compared against
# them: an empty or truncated value that were allowed through would compare
# equal to an equally malformed computed value and bind nothing.
for expectation in "$expected_smoke_sha256" "$expected_source_digest"; do
	if [ "${#expectation}" -ne 64 ] ||
		! printf '%s' "$expectation" | grep -qE '^[0-9a-f]{64}$'; then
		echo "expected digest is not 64 lower-hex characters: $expectation" >&2
		exit 1
	fi
done

smoke_sha256=$(sha256sum "$smoke_bin" | awk '{ print $1 }')
if [ "$smoke_sha256" != "$expected_smoke_sha256" ]; then
	echo "smoke binary is $smoke_sha256, deployer expected $expected_smoke_sha256" >&2
	exit 1
fi

source_digest=$(sha256sum "$source_manifest" | awk '{ print $1 }')
if [ "$source_digest" != "$expected_source_digest" ]; then
	echo "source manifest is $source_digest, deployer expected $expected_source_digest" >&2
	exit 1
fi

mkdir -p "$run_root"
chmod 0700 "$run_root"

evidence_dir=$run_root/evidence
# The audit HMAC key lives here, never inside the evidence directory: sealing
# the MAC key beside the log it authenticates would let anyone holding the
# evidence forge entries.
work_dir=$run_root/work
audit_key=$work_dir/pki/audit.key

# Every input this run's verdict depends on, including the audit verifier's own
# artifact, is recorded in the run root.
sha256sum "$smoke_bin" "$verify_bin" "$audit_bin" "$source_manifest" \
	>"$run_root/binaries.sha256"
cat "$run_root/binaries.sha256"

# Deliberately not piped through tee: a pipeline's exit status is the last
# command's, so `smoke | tee` would report success no matter how the smoke
# exited, and a failed run would be presented as evidence.
# AUDIT-CLOSE known-leak scan, before the writer starts.
#
# This is NOT what makes the credential separate. That comes from provisioning:
# the seed is never copied to this host, and the controller that holds it is a
# different machine with a different identity. This scan catches the obvious
# ways that discipline gets broken — a seed left in a deployment directory, an
# environment variable pointing at one — and a clean result means only that none
# of the known leak shapes were found where it looked.
echo
echo "== scanning for finalizer material left on the writer's host =="
if ! "$audit_bin" \
	-detect-finalizer-leaks \
	-custody-scan "$run_root:$(dirname "$smoke_bin"):$(dirname "$source_manifest")" \
	>"$run_root/finalizer-leak-scan.log" 2>&1; then
	cat "$run_root/finalizer-leak-scan.log" >&2
	echo "finalizer material was found on the audit writer's host" >&2
	exit 1
fi
cat "$run_root/finalizer-leak-scan.log"

echo
echo "== forcing every carrier abort reason =="
if ! "$smoke_bin" \
	-evidence-dir "$evidence_dir" \
	-work-dir "$work_dir" \
	-expected-binary-sha256 "$expected_smoke_sha256" \
	-expected-source-digest "$expected_source_digest" \
	>"$run_root/smoke.log" 2>&1; then
	cat "$run_root/smoke.log"
	echo "conservation smoke failed; evidence is not sealed" >&2
	exit 1
fi
cat "$run_root/smoke.log"

echo
echo "== verifying the sealed audit chain with the real audit verifier =="
if [ ! -f "$audit_key" ]; then
	echo "audit key was not written where the runner expects it: $audit_key" >&2
	exit 1
fi
if ! "$audit_bin" \
	-audit-log "$evidence_dir/carrier-audit.jsonl" \
	-audit-key "$audit_key" \
	>"$run_root/audit-verify.log" 2>&1; then
	cat "$run_root/audit-verify.log"
	echo "audit verifier rejected the sealed carrier trail" >&2
	exit 1
fi
cat "$run_root/audit-verify.log"

# The conservation report is NOT run here. It now requires the terminal
# checkpoint, and the checkpoint cannot be created on this host without
# destroying the custody separation it exists to provide. Retrieve this run root
# to the controller and run scripts/finalize_audit_checkpoint.sh, which closes
# the trail and then runs exactly this verification.
echo
echo "== evidence sealed and CLOSED-PENDING =="
echo "the audit trail is final and the manifest is sealed; the terminal"
echo "checkpoint is created on the controller, not here"

audit_bin_sha256=$(sha256sum "$audit_bin" | awk '{ print $1 }')

echo
echo "RUN_ROOT=$run_root"
echo "EVIDENCE_DIR=$evidence_dir"
echo "SMOKE_BINARY_SHA256=$smoke_sha256"
echo "SMOKE_SOURCE_DIGEST=$source_digest"
echo "AUDIT_BINARY_SHA256=$audit_bin_sha256"
echo "AUDIT_CHECKPOINT_STATE=closed-pending-controller-finalization"
