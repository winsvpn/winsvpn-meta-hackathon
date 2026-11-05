#!/bin/sh
set -eu

# Resumable, fail-closed Phase 1 production-Auto timing matrix for AICORE.
# Each completed batch owns a separately authenticated measurement log and a
# content-addressed evidence archive. Failed or ambiguous batches are never
# skipped; the runner stops so their evidence can be diagnosed.

HARNESS=${HARNESS:-/opt/winn-lab/aicore_auto_e2e.sh}
AUTO_BIN=${AUTO_BIN:-/opt/winn-lab/bin/winn-auto-e2e}
AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
FIXTURE_BIN=${FIXTURE_BIN:-/opt/winn-lab/bin/winn-auto-fixture}
CARRIER_BIN=${CARRIER_BIN:-/opt/winn-lab/bin/winn-carrier-server}
PKI_BIN=${PKI_BIN:-/opt/winn-lab/bin/winn-pki}
TOKEN_ISSUER_BIN=${TOKEN_ISSUER_BIN:-/opt/winn-lab/bin/winn-token-issuer}
TOKEN_BIN=${TOKEN_BIN:-/opt/winn-lab/bin/winn-token}
AUDIT_BIN=${AUDIT_BIN:-/opt/winn-lab/bin/winn-audit}
MEASUREMENT_VERIFY_BIN=${MEASUREMENT_VERIFY_BIN:-/opt/winn-lab/bin/winn-measurement-verify}
MATRIX_VERIFY_BIN=${MATRIX_VERIFY_BIN:-/opt/winn-lab/bin/winn-phase1-matrix-verify}
RESPONDER_BIN=${RESPONDER_BIN:-/opt/winn-lab/bin/winn-h3-e2e}
POSTGRES_SCHEMA=${POSTGRES_SCHEMA:-/opt/winn-lab/schema/postgres_v1.sql}
SOURCE_MANIFEST=${SOURCE_MANIFEST:-/opt/winn-lab/bin/winn-auto-e2e.source.sha256}
PROFILE_CONFIG=${PROFILE_CONFIG:-/opt/winn-lab/config/phase1_auto_impairment_profiles_v2.json}
EXPECTED_PROFILE_SHA256=${EXPECTED_PROFILE_SHA256:-8eedb65b6fa80449b466d7cbdadad050912c0601509d9f6b400ac8bd2b17b225}
# Deliberately not ${VAR:?...}. A ":?" expansion aborts at the top of the file,
# before any policy check has run, so a run that is not permitted to proceed at
# all would be reported as a missing-variable problem. These are validated below,
# after the AUDIT-CLOSE refusal has had its chance to speak.
EXPECTED_SOURCE_DIGEST=${EXPECTED_SOURCE_DIGEST:-}
EXPECTED_AWG_ENGINE_SHA256=${EXPECTED_AWG_ENGINE_SHA256:-}
MATRIX_ID=${MATRIX_ID:-phase1-auto-v1}
# AUDIT-CLOSE. No finalizer credential exists on this host, by design. The
# batches produce closed logs and sealed manifests; the terminal checkpoint that
# commits to each is created on the controller, over retrieved evidence, by
# scripts/finalize_audit_checkpoint.sh. The batch harness runs the carrier as
# root, so a seed stored here would be readable by the very process the
# checkpoint constrains — permission bits are not a boundary against the same
# identity. The absence is asserted below rather than assumed.
MATRIX_ROOT=${MATRIX_ROOT:-/opt/winn-lab/matrices/$MATRIX_ID}
MATRIX_MODE=${MATRIX_MODE:-run}
BATCH_SIZE=${BATCH_SIZE:-100}
ATTEMPTS_PER_CLASS=${ATTEMPTS_PER_CLASS:-}
ALLOW_PARTIAL_MATRIX=${ALLOW_PARTIAL_MATRIX:-0}
PROFILE_FILTER=${PROFILE_FILTER:-}
READINESS_FILTER=${READINESS_FILTER:-}
# Read here, and passed explicitly to every batch below, so an exported value
# in the surrounding unit environment can never reach the harness unseen.
FORCE_CARRIER=${FORCE_CARRIER:-}
FLOCK_BIN=${FLOCK_BIN:-/usr/bin/flock}
JQ_BIN=${JQ_BIN:-/usr/bin/jq}
TIMEOUT_BIN=${TIMEOUT_BIN:-/usr/bin/timeout}
BATCH_TIMEOUT_SECONDS=${BATCH_TIMEOUT_SECONDS:-1800}
ANCHOR_MODE=${ANCHOR_MODE:-disabled}
ANCHOR_PIN_BIN=${ANCHOR_PIN_BIN:-/opt/winn-lab/bin/winn-phase1-anchor-pin}
ANCHOR_SSH_BIN=${ANCHOR_SSH_BIN:-/usr/bin/ssh}
ANCHOR_SSH_KEY=${ANCHOR_SSH_KEY:-}
ANCHOR_SSH_PUBLIC_KEY=${ANCHOR_SSH_PUBLIC_KEY:-}
ANCHOR_KNOWN_HOSTS=${ANCHOR_KNOWN_HOSTS:-}
ANCHOR_PROVIDER_ONE_ID=${ANCHOR_PROVIDER_ONE_ID:-}
ANCHOR_PROVIDER_ONE_HOST=${ANCHOR_PROVIDER_ONE_HOST:-}
ANCHOR_PROVIDER_ONE_PUBLIC_KEY=${ANCHOR_PROVIDER_ONE_PUBLIC_KEY:-}
ANCHOR_PROVIDER_TWO_ID=${ANCHOR_PROVIDER_TWO_ID:-}
ANCHOR_PROVIDER_TWO_HOST=${ANCHOR_PROVIDER_TWO_HOST:-}
ANCHOR_PROVIDER_TWO_PUBLIC_KEY=${ANCHOR_PROVIDER_TWO_PUBLIC_KEY:-}
ANCHOR_TIMEOUT=${ANCHOR_TIMEOUT:-20s}
OPENSSL_BIN=${OPENSSL_BIN:-/usr/bin/openssl}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

case "$MATRIX_MODE" in
preflight | run) ;;
*) fail "MATRIX_MODE must be preflight or run" ;;
esac
case "$ALLOW_PARTIAL_MATRIX" in
0 | 1) ;;
*) fail "ALLOW_PARTIAL_MATRIX must be 0 or 1" ;;
esac

case "$MATRIX_ID" in
	"" | *[!A-Za-z0-9_.-]*) fail "MATRIX_ID is invalid" ;;
esac
case "$BATCH_SIZE" in
	"" | *[!0-9]*) fail "BATCH_SIZE must be a positive integer" ;;
esac
if [ "$BATCH_SIZE" -lt 1 ] || [ "$BATCH_SIZE" -gt 4000 ]; then
	fail "BATCH_SIZE must be within [1,4000]"
fi
case "$BATCH_TIMEOUT_SECONDS" in
	"" | *[!0-9]*)
		fail "BATCH_TIMEOUT_SECONDS must be a positive integer"
		;;
esac
if [ "$BATCH_TIMEOUT_SECONDS" -lt 60 ] ||
	[ "$BATCH_TIMEOUT_SECONDS" -gt 7200 ]; then
	fail "BATCH_TIMEOUT_SECONDS must be within [60,7200]"
fi
# Three modes, and the middle one exists because the other two cannot together
# express a legal full run any more.
#
#   disabled                          exploratory. No anchoring, ever. Partial.
#   controller-deferred-dual-provider-v1
#                                     the full frozen schedule runs HERE and is
#                                     anchored THERE. The producer commits, up
#                                     front and in matrix.env, to the anchor mode
#                                     the controller is required to perform, and
#                                     creates no anchor artifact of any kind.
#   dual-provider-v1                  real anchoring on this host. Refused: see
#                                     the AUDIT-CLOSE block below.
#
# Without the middle mode the policy is impossible to satisfy: a full
# (partial=0) run is required to use dual-provider-v1, and dual-provider-v1 is
# refused here, so no flag combination could start a full run at all. The wrong
# way out of that is to run partial=1 and call the result formal later. This
# mode is the right way: the run really is the full frozen schedule, it really
# is unpromotable until the controller anchors it, and the intent is recorded in
# the matrix metadata before the first batch rather than asserted afterwards.
case "$ANCHOR_MODE" in
	disabled | controller-deferred-dual-provider-v1 | dual-provider-v1) ;;
	*)
		fail "ANCHOR_MODE must be disabled, \
controller-deferred-dual-provider-v1, or dual-provider-v1"
		;;
esac

# The mode the controller is committed to performing. Recorded in matrix.env so
# the commitment is part of the frozen, compared matrix parameters, not a claim
# made about the evidence afterwards.
INTENDED_ANCHOR_MODE=none
if [ "$ANCHOR_MODE" = controller-deferred-dual-provider-v1 ]; then
	INTENDED_ANCHOR_MODE=dual-provider-v1
fi

# AUDIT-CLOSE. This host cannot produce promotable evidence, and must not
# produce anything that looks like it.
#
# A batch sealed here has a final audit log and a sealed base manifest, but no
# terminal checkpoint: the checkpoint is created on the controller, after
# retrieval, because a checkpoint signed on this host would be signed by a
# credential the audit writer could read. Anchoring evidence in that state would
# commit two independent providers to an archive whose trail could still have
# been truncated without detection — the anchor would be a durable, externally
# witnessed attestation to something nobody had checked, and no later flag could
# retract it.
#
# So dual-provider anchoring is refused outright, here, as the FIRST thing that
# happens after ANCHOR_MODE is parsed. This is a policy refusal, not a
# prerequisite failure: whether fifteen executables and a set of provider keys
# happen to be installed is irrelevant to a run that is not permitted to
# proceed, and validating them first would only turn a clear "not allowed" into
# whichever unrelated dependency is missing today.
#
# The controller anchors the CLOSED archive (base evidence plus checkpoint) that
# scripts/finalize_audit_checkpoint.sh produces, and only that archive.
if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
	fail "AUDIT-CLOSE: dual-provider anchoring must run on the controller, over \
the closed archive produced by scripts/finalize_audit_checkpoint.sh; evidence \
sealed here carries no terminal audit checkpoint and is not promotable"
fi

# Only now: the inputs a permitted run needs. Ordered after the refusal above so
# a forbidden run is told it is forbidden, not that it is missing a digest.
if [ -z "$EXPECTED_SOURCE_DIGEST" ]; then
	fail "set EXPECTED_SOURCE_DIGEST"
fi
if [ -z "$EXPECTED_AWG_ENGINE_SHA256" ]; then
	fail "set EXPECTED_AWG_ENGINE_SHA256"
fi
case "$EXPECTED_AWG_ENGINE_SHA256" in
????????????????????????????????????????????????????????????????) ;;
*) fail "EXPECTED_AWG_ENGINE_SHA256 must be a 64-character digest" ;;
esac
case "$EXPECTED_AWG_ENGINE_SHA256" in
*[!0-9a-f]*) fail "EXPECTED_AWG_ENGINE_SHA256 must be lowercase hexadecimal" ;;
esac
for executable in "$HARNESS" "$AUTO_BIN" "$AWG_BIN" "$AWG_ENGINE" \
	"$FIXTURE_BIN" "$CARRIER_BIN" "$PKI_BIN" "$TOKEN_ISSUER_BIN" \
	"$TOKEN_BIN" "$AUDIT_BIN" "$MEASUREMENT_VERIFY_BIN" \
	"$MATRIX_VERIFY_BIN" "$RESPONDER_BIN" "$FLOCK_BIN" "$JQ_BIN" \
	"$TIMEOUT_BIN"; do
	if [ ! -x "$executable" ]; then
		fail "required executable is missing: $executable"
	fi
done
if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
	for executable in "$ANCHOR_PIN_BIN" "$ANCHOR_SSH_BIN" "$OPENSSL_BIN"; do
		if [ ! -x "$executable" ]; then
			fail "required anchor executable is missing: $executable"
		fi
	done
	for anchor_file in "$ANCHOR_SSH_KEY" "$ANCHOR_SSH_PUBLIC_KEY" \
		"$ANCHOR_KNOWN_HOSTS" "$ANCHOR_PROVIDER_ONE_PUBLIC_KEY" \
		"$ANCHOR_PROVIDER_TWO_PUBLIC_KEY"; do
		if [ ! -f "$anchor_file" ]; then
			fail "required frozen anchor input is missing: $anchor_file"
		fi
	done
	if [ -z "$ANCHOR_PROVIDER_ONE_ID" ] ||
		[ -z "$ANCHOR_PROVIDER_TWO_ID" ] ||
		[ "$ANCHOR_PROVIDER_ONE_ID" = "$ANCHOR_PROVIDER_TWO_ID" ] ||
		[ -z "$ANCHOR_PROVIDER_ONE_HOST" ] ||
		[ -z "$ANCHOR_PROVIDER_TWO_HOST" ] ||
		[ "$ANCHOR_PROVIDER_ONE_HOST" = "$ANCHOR_PROVIDER_TWO_HOST" ]; then
		fail "two distinct anchor providers are required"
	fi
	if [ "$BATCH_SIZE" -ne 100 ]; then
		fail "dual-provider formal anchoring requires 100-attempt batches"
	fi
	anchor_decode_one=$(mktemp)
	anchor_decode_two=$(mktemp)
	tr -d '[:space:]' <"$ANCHOR_PROVIDER_ONE_PUBLIC_KEY" |
		"$OPENSSL_BIN" base64 -d -A >"$anchor_decode_one" ||
		fail "first provider public key is not valid base64"
	tr -d '[:space:]' <"$ANCHOR_PROVIDER_TWO_PUBLIC_KEY" |
		"$OPENSSL_BIN" base64 -d -A >"$anchor_decode_two" ||
		fail "second provider public key is not valid base64"
	if [ "$(wc -c <"$anchor_decode_one" | tr -d '[:space:]')" -ne 32 ] ||
		[ "$(wc -c <"$anchor_decode_two" | tr -d '[:space:]')" -ne 32 ]; then
		rm -f "$anchor_decode_one" "$anchor_decode_two"
		fail "provider receipt keys must be Ed25519 public keys"
	fi
	if cmp -s "$anchor_decode_one" "$anchor_decode_two"; then
		rm -f "$anchor_decode_one" "$anchor_decode_two"
		fail "anchor providers must use distinct receipt keys"
	fi
	anchor_provider_one_key_id=$(
		sha256sum "$anchor_decode_one" | awk '{ print $1 }'
	)
	anchor_provider_two_key_id=$(
		sha256sum "$anchor_decode_two" | awk '{ print $1 }'
	)
	rm -f "$anchor_decode_one" "$anchor_decode_two"
	anchor_known_hosts_sha256=$(
		sha256sum "$ANCHOR_KNOWN_HOSTS" | awk '{ print $1 }'
	)
fi
for source_file in "$SOURCE_MANIFEST" "$PROFILE_CONFIG" "$POSTGRES_SCHEMA"; do
	if [ ! -f "$source_file" ]; then
		fail "required frozen input is missing: $source_file"
	fi
done

actual_profile_sha=$(sha256sum "$PROFILE_CONFIG" | awk '{ print $1 }')
if [ "$actual_profile_sha" != "$EXPECTED_PROFILE_SHA256" ]; then
	fail "impairment profile digest mismatch"
fi
profile_schema=$(
	"$JQ_BIN" -er '.schema' "$PROFILE_CONFIG"
)
if [ "$profile_schema" != "winn-phase1-auto-impairment-profiles/v2" ]; then
	fail "Phase 1 matrix requires the cluster-aware v2 profile"
fi
frozen_batch_size=$(
	"$JQ_BIN" -er '.batch_size' "$PROFILE_CONFIG"
)
schedule_seed=$(
	"$JQ_BIN" -er '.schedule_seed' "$PROFILE_CONFIG"
)
case "$schedule_seed" in
	????????????????????????????????????????????????????????????????) ;;
	*) fail "schedule seed must be a 64-character digest" ;;
esac
case "$schedule_seed" in
	*[!0-9a-f]*) fail "schedule seed must be lowercase hexadecimal" ;;
esac
if [ "$BATCH_SIZE" -ne "$frozen_batch_size" ] &&
	[ "$ALLOW_PARTIAL_MATRIX" -ne 1 ]; then
	fail "full matrix batch size differs from the frozen cluster size"
fi
embedded_source_digest=$("$AUTO_BIN" -print-source-digest)
if [ "$embedded_source_digest" != "$EXPECTED_SOURCE_DIGEST" ]; then
	fail "Auto binary source digest mismatch"
fi
actual_awg_engine_sha256=$(
	sha256sum "$AWG_ENGINE" | awk '{ print $1 }'
)
if [ "$actual_awg_engine_sha256" != "$EXPECTED_AWG_ENGINE_SHA256" ]; then
	fail "Winn AWG engine digest mismatch"
fi
manifest_digest=$(sha256sum "$SOURCE_MANIFEST" | awk '{ print $1 }')
if [ "$manifest_digest" != "$EXPECTED_SOURCE_DIGEST" ]; then
	fail "source manifest digest differs from embedded source digest"
fi

frozen_attempts=$(
	"$JQ_BIN" -er '.attempts_per_readiness_per_profile' "$PROFILE_CONFIG"
)
profiles=$(
	"$JQ_BIN" -er '
		.profiles |
		if type == "array" and
			length >= 1 and length <= 64 and
			all(.[]; type == "object" and
				(.id | type == "string" and
				 test("^[A-Za-z0-9_.-]{1,64}$"))) and
			([.[].id] | unique | length) == length
		then .[].id
		else error("invalid or duplicate profile IDs")
		end
	' "$PROFILE_CONFIG"
)
readiness_classes=$(
	"$JQ_BIN" -er '
		.readiness_classes |
		if type == "array" and
			length >= 1 and length <= 2 and
			all(.[]; . == "warm" or . == "cold") and
			(unique | length) == length
		then .[]
		else error("invalid or duplicate readiness classes")
		end
	' "$PROFILE_CONFIG"
)
if [ -z "$ATTEMPTS_PER_CLASS" ]; then
	ATTEMPTS_PER_CLASS=$frozen_attempts
fi
case "$ATTEMPTS_PER_CLASS" in
	"" | *[!0-9]*)
		fail "ATTEMPTS_PER_CLASS must be a positive integer"
		;;
esac
if [ "$ATTEMPTS_PER_CLASS" -lt 1 ]; then
	fail "ATTEMPTS_PER_CLASS must be positive"
fi
if [ "$ATTEMPTS_PER_CLASS" -ne "$frozen_attempts" ] &&
	[ "$ALLOW_PARTIAL_MATRIX" -ne 1 ]; then
	fail "non-frozen attempt count requires ALLOW_PARTIAL_MATRIX=1"
fi
if [ -n "$PROFILE_FILTER" ] && [ "$ALLOW_PARTIAL_MATRIX" -ne 1 ]; then
	fail "PROFILE_FILTER requires ALLOW_PARTIAL_MATRIX=1"
fi
if [ -n "$PROFILE_FILTER" ]; then
	profile_filter_found=0
	for frozen_profile in $profiles; do
		if [ "$PROFILE_FILTER" = "$frozen_profile" ]; then
			profile_filter_found=1
			break
		fi
	done
	if [ "$profile_filter_found" -ne 1 ]; then
		fail "PROFILE_FILTER is not in the frozen profile configuration"
	fi
fi
case "$READINESS_FILTER" in
"" | warm | cold) ;;
*) fail "READINESS_FILTER must be empty, warm, or cold" ;;
esac
if [ -n "$READINESS_FILTER" ] && [ "$ALLOW_PARTIAL_MATRIX" -ne 1 ]; then
	fail "READINESS_FILTER requires ALLOW_PARTIAL_MATRIX=1"
fi
if [ -n "$READINESS_FILTER" ]; then
	readiness_filter_found=0
	for frozen_readiness in $readiness_classes; do
		if [ "$READINESS_FILTER" = "$frozen_readiness" ]; then
			readiness_filter_found=1
			break
		fi
	done
	if [ "$readiness_filter_found" -ne 1 ]; then
		fail "READINESS_FILTER is not in the frozen profile configuration"
	fi
fi
# A full run must be headed for dual-provider anchoring. On this host that means
# the deferred mode, because the immediate mode is refused above.
if [ "$ALLOW_PARTIAL_MATRIX" -ne 1 ] &&
	[ "$ANCHOR_MODE" != controller-deferred-dual-provider-v1 ]; then
	fail "full formal matrix requires \
ANCHOR_MODE=controller-deferred-dual-provider-v1: the schedule runs here and \
the dual-provider anchors are created by the controller over closed archives"
fi
if [ -n "$FORCE_CARRIER" ] && [ "$ANCHOR_MODE" != disabled ]; then
	fail "anchor-bound evidence forbids FORCE_CARRIER"
fi

# Deferred means deferred. If this host holds anchor credentials or endpoints,
# the separation the mode claims is not real: something here could anchor, and
# the controller's later verification would be checking a property that was
# never enforced. Refuse rather than trust the operator not to have set them.
if [ "$ANCHOR_MODE" = controller-deferred-dual-provider-v1 ]; then
	for anchor_input in \
		"$ANCHOR_SSH_KEY" \
		"$ANCHOR_SSH_PUBLIC_KEY" \
		"$ANCHOR_KNOWN_HOSTS" \
		"$ANCHOR_PROVIDER_ONE_ID" \
		"$ANCHOR_PROVIDER_ONE_HOST" \
		"$ANCHOR_PROVIDER_ONE_PUBLIC_KEY" \
		"$ANCHOR_PROVIDER_TWO_ID" \
		"$ANCHOR_PROVIDER_TWO_HOST" \
		"$ANCHOR_PROVIDER_TWO_PUBLIC_KEY"; do
		if [ -n "$anchor_input" ]; then
			fail "AUDIT-CLOSE: ANCHOR_MODE=controller-deferred-dual-provider-v1 \
forbids anchor credentials or endpoints on the producing host; all anchoring \
inputs belong to the controller"
		fi
	done
fi

# AUDIT-CLOSE known-leak scan. Every batch below runs the carrier as root, and
# the carrier is the audit writer. The separation this record depends on comes
# from never provisioning the finalizer seed to this host at all; the scan below
# only catches the obvious ways that gets broken, and a clean result is not
# proof of absence.
if ! "$AUDIT_BIN" \
	-detect-finalizer-leaks \
	-custody-scan "$MATRIX_ROOT:$(dirname "$AUDIT_BIN"):$(dirname "$HARNESS")"; then
	fail "audit finalizer material was found on the audit writer's host"
fi

if [ "$MATRIX_MODE" = preflight ]; then
	runner_path=$(readlink -f "$0")
	execution_inventory_sha256=$(
		sha256sum \
			"$runner_path" \
			"$HARNESS" \
			"$AUTO_BIN" \
			"$AWG_BIN" \
			"$AWG_ENGINE" \
			"$FIXTURE_BIN" \
			"$CARRIER_BIN" \
			"$PKI_BIN" \
			"$TOKEN_ISSUER_BIN" \
			"$TOKEN_BIN" \
			"$AUDIT_BIN" \
			"$MEASUREMENT_VERIFY_BIN" \
			"$MATRIX_VERIFY_BIN" \
			"$RESPONDER_BIN" \
			"$FLOCK_BIN" \
			"$JQ_BIN" \
			"$TIMEOUT_BIN" \
			"$POSTGRES_SCHEMA" \
			"$SOURCE_MANIFEST" \
			"$PROFILE_CONFIG" |
			sha256sum |
			awk '{ print $1 }'
	)
	echo "MATRIX_PREFLIGHT schema=winn-phase1-auto-matrix-preflight/v1 \
matrix_id=$MATRIX_ID source_digest=$EXPECTED_SOURCE_DIGEST \
awg_engine_sha256=$actual_awg_engine_sha256 \
profile_sha256=$actual_profile_sha \
execution_inventory_sha256=$execution_inventory_sha256 \
anchor_mode=$ANCHOR_MODE partial=$ALLOW_PARTIAL_MATRIX status=ready \
profile_filter=${PROFILE_FILTER:-all} \
readiness_filter=${READINESS_FILTER:-all} mutation=none"
	exit 0
fi

mkdir -p "$MATRIX_ROOT" "$MATRIX_ROOT/evidence" \
	"$MATRIX_ROOT/batches" "$MATRIX_ROOT/logs" \
	"$MATRIX_ROOT/exclusions"
chmod 0700 "$MATRIX_ROOT" "$MATRIX_ROOT/evidence" \
	"$MATRIX_ROOT/batches" "$MATRIX_ROOT/logs" \
	"$MATRIX_ROOT/exclusions"
exec 9>"$MATRIX_ROOT/matrix.lock"
if ! "$FLOCK_BIN" -n 9; then
	fail "another process owns matrix $MATRIX_ID"
fi
if [ -e "$MATRIX_ROOT/INVALID" ]; then
	fail "matrix is permanently invalidated; retain it and start a new matrix ID"
fi

runner_path=$(readlink -f "$0")
execution_inventory_candidate="$MATRIX_ROOT/execution-inventory.sha256.candidate"
sha256sum \
	"$runner_path" \
	"$HARNESS" \
	"$AUTO_BIN" \
	"$AWG_BIN" \
	"$AWG_ENGINE" \
	"$FIXTURE_BIN" \
	"$CARRIER_BIN" \
	"$PKI_BIN" \
	"$TOKEN_ISSUER_BIN" \
	"$TOKEN_BIN" \
	"$AUDIT_BIN" \
	"$MEASUREMENT_VERIFY_BIN" \
	"$MATRIX_VERIFY_BIN" \
	"$RESPONDER_BIN" \
	"$FLOCK_BIN" \
	"$JQ_BIN" \
	"$TIMEOUT_BIN" \
	"$POSTGRES_SCHEMA" \
	"$SOURCE_MANIFEST" \
	"$PROFILE_CONFIG" \
	>"$execution_inventory_candidate"
if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
	sha256sum \
		"$ANCHOR_PIN_BIN" \
		"$ANCHOR_SSH_BIN" \
		"$OPENSSL_BIN" \
		"$ANCHOR_SSH_PUBLIC_KEY" \
		"$ANCHOR_KNOWN_HOSTS" \
		"$ANCHOR_PROVIDER_ONE_PUBLIC_KEY" \
		"$ANCHOR_PROVIDER_TWO_PUBLIC_KEY" \
		>>"$execution_inventory_candidate"
fi
execution_inventory="$MATRIX_ROOT/execution-inventory.sha256"
if [ -f "$execution_inventory" ]; then
	cmp -s "$execution_inventory_candidate" "$execution_inventory" ||
		fail "matrix execution inventory changed"
	rm -f "$execution_inventory_candidate"
else
	mv "$execution_inventory_candidate" "$execution_inventory"
	chmod 0600 "$execution_inventory"
fi
execution_inventory_sha256=$(
	sha256sum "$execution_inventory" | awk '{ print $1 }'
)

if [ -f "$MATRIX_ROOT/profile-config.json" ]; then
	cmp -s "$PROFILE_CONFIG" "$MATRIX_ROOT/profile-config.json" ||
		fail "matrix profile configuration changed"
else
	cp "$PROFILE_CONFIG" "$MATRIX_ROOT/profile-config.json"
fi
if [ -f "$MATRIX_ROOT/source-manifest.sha256" ]; then
	cmp -s "$SOURCE_MANIFEST" "$MATRIX_ROOT/source-manifest.sha256" ||
		fail "matrix source manifest changed"
else
	cp "$SOURCE_MANIFEST" "$MATRIX_ROOT/source-manifest.sha256"
fi

schedule_candidate="$MATRIX_ROOT/schedule.tsv.candidate"
schedule_sorted="$MATRIX_ROOT/schedule.tsv.generated"
: >"$schedule_candidate"
batch_index=1
class_offset=0
while [ "$class_offset" -lt "$ATTEMPTS_PER_CLASS" ]; do
	remaining=$((ATTEMPTS_PER_CLASS - class_offset))
	current_attempts=$BATCH_SIZE
	if [ "$remaining" -lt "$current_attempts" ]; then
		current_attempts=$remaining
	fi
	for profile in $profiles; do
		if [ -n "$PROFILE_FILTER" ] &&
			[ "$profile" != "$PROFILE_FILTER" ]; then
			continue
		fi
		case "$profile" in
			"" | *[!A-Za-z0-9_.-]*)
				fail "profile ID is invalid: $profile"
				;;
		esac
		for readiness in $readiness_classes; do
			if [ -n "$READINESS_FILTER" ] &&
				[ "$readiness" != "$READINESS_FILTER" ]; then
				continue
			fi
			case "$readiness" in
				warm | cold) ;;
				*) fail "readiness class is invalid: $readiness" ;;
			esac
			batch_key=$(
				printf '%s--%s--b%03d' \
					"$profile" "$readiness" "$batch_index"
			)
			order_digest=$(
				printf '%s' \
					"$schedule_seed:$batch_index:$profile:$readiness" |
					sha256sum |
					awk '{ print $1 }'
			)
			printf '%06d\t%s\t%s\t%s\t%s\t%s\n' \
				"$batch_index" \
				"$order_digest" \
				"$batch_key" \
				"$profile" \
				"$readiness" \
				"$current_attempts" \
				>>"$schedule_candidate"
		done
	done
	class_offset=$((class_offset + current_attempts))
	batch_index=$((batch_index + 1))
done
LC_ALL=C sort -t '	' -k1,1n -k2,2 "$schedule_candidate" \
	>"$schedule_sorted"
rm -f "$schedule_candidate"
schedule_file="$MATRIX_ROOT/schedule.tsv"
if [ -f "$schedule_file" ]; then
	cmp -s "$schedule_sorted" "$schedule_file" ||
		fail "matrix randomized schedule changed"
	rm -f "$schedule_sorted"
else
	mv "$schedule_sorted" "$schedule_file"
	chmod 0600 "$schedule_file"
fi
schedule_sha256=$(sha256sum "$schedule_file" | awk '{ print $1 }')
expected_batch_count=$(wc -l <"$schedule_file" | tr -d '[:space:]')
if [ "$expected_batch_count" -lt 1 ]; then
	fail "selected matrix schedule is empty"
fi
auto_artifact_sha256=$(sha256sum "$AUTO_BIN" | awk '{ print $1 }')

invalidate_anchor() {
	anchor_reason=$1
	anchor_invalidated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	if [ -e "$MATRIX_ROOT/INVALID" ]; then
		fail "matrix is already invalid while recording anchor failure"
	fi
	{
		echo "schema=winn-phase1-auto-matrix-invalid/v2"
		echo "matrix_id=$MATRIX_ID"
		echo "invalidated_at_utc=$anchor_invalidated_at"
		echo "source_digest=$EXPECTED_SOURCE_DIGEST"
		echo "schedule_sha256=$schedule_sha256"
		echo "reason=$anchor_reason"
	} >"$MATRIX_ROOT/INVALID.tmp"
	chmod 0600 "$MATRIX_ROOT/INVALID.tmp"
	mv "$MATRIX_ROOT/INVALID.tmp" "$MATRIX_ROOT/INVALID"
}

freeze_anchor_file() {
	anchor_source=$1
	anchor_destination=$2
	if [ -f "$anchor_destination" ]; then
		cmp -s "$anchor_source" "$anchor_destination" ||
			fail "frozen anchor input changed: $anchor_destination"
	else
		cp "$anchor_source" "$anchor_destination"
		chmod 0600 "$anchor_destination"
	fi
}

anchor_pin_or_pause() {
	anchor_pending=$1
	anchor_request=$2
	anchor_previous_one=$3
	anchor_previous_two=$4
	set +e
	"$ANCHOR_PIN_BIN" \
		-pending-directory "$anchor_pending" \
		-request "$anchor_request" \
		-ssh-binary "$ANCHOR_SSH_BIN" \
		-ssh-key "$ANCHOR_SSH_KEY" \
		-known-hosts "$ANCHOR_KNOWN_HOSTS" \
		-timeout "$ANCHOR_TIMEOUT" \
		-provider-one-id "$ANCHOR_PROVIDER_ONE_ID" \
		-provider-one-host "$ANCHOR_PROVIDER_ONE_HOST" \
		-provider-one-public-key "$ANCHOR_PROVIDER_ONE_PUBLIC_KEY" \
		-provider-one-previous-receipt "$anchor_previous_one" \
		-provider-two-id "$ANCHOR_PROVIDER_TWO_ID" \
		-provider-two-host "$ANCHOR_PROVIDER_TWO_HOST" \
		-provider-two-public-key "$ANCHOR_PROVIDER_TWO_PUBLIC_KEY" \
		-provider-two-previous-receipt "$anchor_previous_two"
	anchor_status=$?
	set -e
	if [ "$anchor_status" -eq 75 ]; then
		echo "MATRIX_ANCHOR_PAUSED pending=$anchor_pending" >&2
		exit 75
	fi
	if [ "$anchor_status" -ne 0 ]; then
		invalidate_anchor provider_anchor_permanent_failure
		fail "provider archive anchor permanently failed"
	fi
}

invalidate_batch() {
	abort_status=$1
	abort_reason=$2
	abort_finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	abort_archive="$evidence_directory.closed-pending.tar.gz"
	abort_archive_digest=absent
	abort_measurement_count=0
	abort_measurement_digest=absent
	if [ -f "$abort_archive" ]; then
		abort_archive_digest=$(
			sha256sum "$abort_archive" | awk '{ print $1 }'
		)
	fi
	if [ -f "$evidence_directory/attempts.jsonl" ]; then
		abort_measurement_count=$(
			wc -l <"$evidence_directory/attempts.jsonl" |
				tr -d '[:space:]'
		)
		abort_measurement_digest=$(
			sha256sum "$evidence_directory/attempts.jsonl" |
				awk '{ print $1 }'
		)
	fi
	exclusion_file="$MATRIX_ROOT/exclusions/$batch_key.abort"
	if [ -e "$exclusion_file" ]; then
		fail "batch $batch_key already has an immutable exclusion record"
	fi
	{
		echo "schema=winn-phase1-auto-matrix-exclusion/v2"
		echo "matrix_id=$MATRIX_ID"
		echo "protocol_version=winn/3"
		echo "source_digest=$EXPECTED_SOURCE_DIGEST"
		echo "schedule_sha256=$schedule_sha256"
		echo "batch_key=$batch_key"
		echo "randomized_block=$block_index"
		echo "order_digest=$order_digest"
		echo "profile=$profile"
		echo "readiness=$readiness"
		echo "scheduled_attempts=$current_attempts"
		echo "started_at_utc=$started_at"
		echo "finished_at_utc=$abort_finished_at"
		echo "exit_status=$abort_status"
		echo "reason=$abort_reason"
		echo "recorded_attempts=$abort_measurement_count"
		echo "measurement_sha256=$abort_measurement_digest"
		echo "archive=$abort_archive"
		echo "archive_sha256=$abort_archive_digest"
	} >"$exclusion_file.tmp"
	chmod 0600 "$exclusion_file.tmp"
	mv "$exclusion_file.tmp" "$exclusion_file"
	exclusion_digest=$(sha256sum "$exclusion_file" | awk '{ print $1 }')
	{
		echo "schema=winn-phase1-auto-matrix-invalid/v2"
		echo "matrix_id=$MATRIX_ID"
		echo "invalidated_at_utc=$abort_finished_at"
		echo "source_digest=$EXPECTED_SOURCE_DIGEST"
		echo "schedule_sha256=$schedule_sha256"
		echo "batch_key=$batch_key"
		echo "exclusion_sha256=$exclusion_digest"
	} >"$MATRIX_ROOT/INVALID.tmp"
	chmod 0600 "$MATRIX_ROOT/INVALID.tmp"
	mv "$MATRIX_ROOT/INVALID.tmp" "$MATRIX_ROOT/INVALID"
}

{
	echo "schema=winn-phase1-auto-matrix/v3"
	echo "matrix_id=$MATRIX_ID"
	echo "protocol_version=winn/3"
	echo "source_digest=$EXPECTED_SOURCE_DIGEST"
	echo "awg_engine_sha256=$EXPECTED_AWG_ENGINE_SHA256"
	echo "profile_sha256=$EXPECTED_PROFILE_SHA256"
	echo "attempts_per_readiness_per_profile=$ATTEMPTS_PER_CLASS"
	echo "batch_size=$BATCH_SIZE"
	echo "schedule_seed=$schedule_seed"
	echo "schedule_sha256=$schedule_sha256"
	echo "execution_inventory_sha256=$execution_inventory_sha256"
	echo "auto_artifact_sha256=$auto_artifact_sha256"
	echo "expected_batch_count=$expected_batch_count"
	echo "anchor_mode=$ANCHOR_MODE"
	echo "intended_anchor_mode=$INTENDED_ANCHOR_MODE"
	echo "anchor_schema=winn-phase1-archive-pin/v1"
	echo "anchor_provider_one_id=$ANCHOR_PROVIDER_ONE_ID"
	echo "anchor_provider_one_key_id=${anchor_provider_one_key_id:-}"
	echo "anchor_provider_two_id=$ANCHOR_PROVIDER_TWO_ID"
	echo "anchor_provider_two_key_id=${anchor_provider_two_key_id:-}"
	echo "anchor_known_hosts_sha256=${anchor_known_hosts_sha256:-}"
	echo "batch_timeout_seconds=$BATCH_TIMEOUT_SECONDS"
	echo "partial=$ALLOW_PARTIAL_MATRIX"
	echo "profile_filter=$PROFILE_FILTER"
	echo "readiness_filter=$READINESS_FILTER"
} >"$MATRIX_ROOT/matrix.env.tmp"
if [ -f "$MATRIX_ROOT/matrix.env" ]; then
	cmp -s "$MATRIX_ROOT/matrix.env.tmp" "$MATRIX_ROOT/matrix.env" ||
		fail "matrix parameters changed"
	rm -f "$MATRIX_ROOT/matrix.env.tmp"
else
	mv "$MATRIX_ROOT/matrix.env.tmp" "$MATRIX_ROOT/matrix.env"
fi

anchor_previous_one=
anchor_previous_two=
if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
	anchor_root="$MATRIX_ROOT/anchors"
	anchor_pending_root="$anchor_root/pending"
	anchor_committed_root="$anchor_root/committed"
	mkdir -p "$anchor_root" "$anchor_pending_root" "$anchor_committed_root"
	chmod 0700 "$anchor_root" "$anchor_pending_root" "$anchor_committed_root"
	freeze_anchor_file \
		"$ANCHOR_PROVIDER_ONE_PUBLIC_KEY" \
		"$anchor_root/provider-one.ed25519.pub"
	freeze_anchor_file \
		"$ANCHOR_PROVIDER_TWO_PUBLIC_KEY" \
		"$anchor_root/provider-two.ed25519.pub"
	freeze_anchor_file \
		"$ANCHOR_KNOWN_HOSTS" \
		"$anchor_root/known_hosts"
	freeze_anchor_file \
		"$ANCHOR_SSH_PUBLIC_KEY" \
		"$anchor_root/anchor-transport-identity.pub"
	genesis_request="$anchor_root/genesis-request.json"
	genesis_candidate="$anchor_root/genesis-request.json.candidate"
	"$JQ_BIN" -cn \
		--arg schema "winn-phase1-archive-pin/v1" \
		--arg kind genesis \
		--arg matrix "$MATRIX_ID" \
		--arg source "$EXPECTED_SOURCE_DIGEST" \
		--arg artifact "$auto_artifact_sha256" \
		--arg profile "$EXPECTED_PROFILE_SHA256" \
		--arg schedule "$schedule_sha256" \
		--argjson expected "$expected_batch_count" \
		'{schema:$schema,kind:$kind,matrix_id:$matrix,
		  source_digest:$source,auto_artifact_digest:$artifact,
		  profile_digest:$profile,schedule_digest:$schedule,
		  expected_batch_count:$expected,ordinal:0}' \
		>"$genesis_candidate"
	if [ -f "$genesis_request" ]; then
		cmp -s "$genesis_candidate" "$genesis_request" ||
			fail "anchor genesis request changed"
		rm -f "$genesis_candidate"
	else
		mv "$genesis_candidate" "$genesis_request"
		chmod 0600 "$genesis_request"
	fi
	genesis_pending="$anchor_pending_root/000000-genesis.pin-pending"
	genesis_committed="$anchor_committed_root/000000-genesis"
	if [ ! -d "$genesis_committed" ]; then
		mkdir -m 0700 -p "$genesis_pending"
		zero_digest=0000000000000000000000000000000000000000000000000000000000000000
		anchor_pin_or_pause \
			"$genesis_pending" "$genesis_request" \
			"$zero_digest" "$zero_digest"
		mv "$genesis_pending" "$genesis_committed"
	fi
	anchor_previous_one=$(
		tr -d '[:space:]' \
			<"$genesis_committed/provider-one.receipt.json.sha256"
	)
	anchor_previous_two=$(
		tr -d '[:space:]' \
			<"$genesis_committed/provider-two.receipt.json.sha256"
	)
fi

sequence=0
completed_total=0
schedule_tab=$(printf '\t')
expected_total=$(
	awk -F "$schedule_tab" '{ total += $6 } END { print total + 0 }' \
		"$schedule_file"
)

exec 8<"$schedule_file"
while IFS="$schedule_tab" read -r block_index order_digest batch_key \
	profile readiness current_attempts <&8; do
	sequence=$((sequence + 1))
	# AUDIT-CLOSE. Deliberately NOT "$batch_key.done".
	#
	# A pre-checkpoint batch must not produce anything that looks like a
	# completion marker to a consumer that has never heard of the checkpoint.
	# Adding a promotional=0 field inside a .done file would not do: unknown
	# keys are routinely ignored, so the file's NAME is what has to carry the
	# state. The terminal .done is written by the controller, after it has
	# verified the checkpoint sidecar — see WINN_PROTOCOL_V3 AUDIT-CLOSE.
	done_file="$MATRIX_ROOT/batches/$batch_key.closed-pending"
	anchor_slot=$(printf '%06d-%s' "$sequence" "$batch_key")
	anchor_committed_directory=
	if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
		anchor_committed_directory="$anchor_committed_root/$anchor_slot"
	fi
	if [ -f "$done_file" ]; then
		recorded_schema=$(
			awk -F= '$1 == "schema" { print $2 }' "$done_file"
		)
		recorded_block=$(
			awk -F= '$1 == "randomized_block" { print $2 }' "$done_file"
		)
		recorded_order=$(
			awk -F= '$1 == "order_digest" { print $2 }' "$done_file"
		)
		recorded_profile=$(
			awk -F= '$1 == "profile" { print $2 }' "$done_file"
		)
		recorded_readiness=$(
			awk -F= '$1 == "readiness" { print $2 }' "$done_file"
		)
		recorded_attempts=$(
			awk -F= '$1 == "attempts" { print $2 }' "$done_file"
		)
		if [ "$recorded_schema" != \
			"winn-phase1-auto-matrix-batch-closed-pending/v3" ] ||
			[ "$recorded_block" != "$block_index" ] ||
			[ "$recorded_order" != "$order_digest" ] ||
			[ "$recorded_profile" != "$profile" ] ||
			[ "$recorded_readiness" != "$readiness" ] ||
			[ "$recorded_attempts" != "$current_attempts" ]; then
			fail "completed batch $batch_key differs from its schedule row"
		fi
		if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
			if [ ! -d "$anchor_committed_directory" ]; then
				fail "completed batch lacks committed dual-provider receipts"
			fi
			recorded_anchor_one=$(
				awk -F= \
					'$1 == "anchor_provider_one_receipt_sha256" {
						print $2
					}' "$done_file"
			)
			recorded_anchor_two=$(
				awk -F= \
					'$1 == "anchor_provider_two_receipt_sha256" {
						print $2
					}' "$done_file"
			)
			actual_anchor_one=$(
				tr -d '[:space:]' \
					<"$anchor_committed_directory/provider-one.receipt.json.sha256"
			)
			actual_anchor_two=$(
				tr -d '[:space:]' \
					<"$anchor_committed_directory/provider-two.receipt.json.sha256"
			)
			if [ "$recorded_anchor_one" != "$actual_anchor_one" ] ||
				[ "$recorded_anchor_two" != "$actual_anchor_two" ]; then
				fail "completed batch anchor receipts changed"
			fi
			anchor_previous_one=$actual_anchor_one
			anchor_previous_two=$actual_anchor_two
		fi
		completed_total=$((completed_total + recorded_attempts))
		continue
	fi

	run_token=$(printf 'm%04d' "$sequence")
	run_id="$MATRIX_ID-$batch_key"
	evidence_directory="$MATRIX_ROOT/evidence/auto-e2e-$run_id"
	anchor_pending_directory=
	anchor_resume_directory=
	if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
		anchor_pending_directory="$anchor_pending_root/$anchor_slot.pin-pending"
		if [ -d "$anchor_pending_directory" ] &&
			[ -d "$anchor_committed_directory" ]; then
			invalidate_anchor conflicting_anchor_resume_state
			fail "batch has both pending and committed anchor state"
		fi
		if [ -d "$anchor_pending_directory" ]; then
			anchor_resume_directory=$anchor_pending_directory
		elif [ -d "$anchor_committed_directory" ]; then
			anchor_resume_directory=$anchor_committed_directory
		fi
	fi
	if { [ -e "$evidence_directory" ] ||
		[ -e "$evidence_directory.closed-pending.tar.gz" ]; } &&
		[ -z "$anchor_resume_directory" ]; then
		started_at=unknown
		invalidate_batch 125 preexisting_uncommitted_evidence
		fail "uncommitted evidence permanently invalidated matrix at $batch_key"
	fi
	batch_log="$MATRIX_ROOT/logs/$batch_key.log"
	if [ -n "$anchor_resume_directory" ]; then
		started_at=$(
			awk -F= '$1 == "started_at_utc" { print $2 }' \
				"$anchor_resume_directory/batch-meta.env"
		)
		if [ -z "$started_at" ]; then
			invalidate_anchor incomplete_anchor_resume_metadata
			fail "anchor resume metadata is incomplete"
		fi
	else
		started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
		if ! sha256sum -c "$execution_inventory" >/dev/null; then
			invalidate_batch 126 execution_inventory_precheck_failed
			fail "execution inventory changed before batch: $batch_key"
		fi
		set +e
		RUN_TOKEN="$run_token" \
			AUTO_BIN="$AUTO_BIN" \
			AWG_BIN="$AWG_BIN" \
			AWG_ENGINE="$AWG_ENGINE" \
			FIXTURE_BIN="$FIXTURE_BIN" \
			CARRIER_BIN="$CARRIER_BIN" \
			PKI_BIN="$PKI_BIN" \
			TOKEN_ISSUER_BIN="$TOKEN_ISSUER_BIN" \
			TOKEN_BIN="$TOKEN_BIN" \
			AUDIT_BIN="$AUDIT_BIN" \
			MEASUREMENT_VERIFY_BIN="$MEASUREMENT_VERIFY_BIN" \
			EXECUTION_INVENTORY="$execution_inventory" \
			EXPECTED_EXECUTION_INVENTORY_SHA256="$execution_inventory_sha256" \
			RESPONDER_BIN="$RESPONDER_BIN" \
			POSTGRES_SCHEMA="$POSTGRES_SCHEMA" \
			DIRECT_INITIAL_OUTER_DROP=0s \
			DIRECT_CLICK_DELAY=0s \
			FORCE_CARRIER="$FORCE_CARRIER" \
			ATTEMPTS="$current_attempts" \
			READINESS="$readiness" \
			IMPAIRMENT_ID="$profile" \
			HOLD=0s \
			RUN_ID="$run_id" \
			EVIDENCE_ROOT="$MATRIX_ROOT/evidence" \
			EXPECTED_SOURCE_DIGEST="$EXPECTED_SOURCE_DIGEST" \
			SOURCE_MANIFEST="$SOURCE_MANIFEST" \
			"$TIMEOUT_BIN" \
			--signal=TERM \
			--kill-after=30s \
			"${BATCH_TIMEOUT_SECONDS}s" \
			"$HARNESS" >"$batch_log" 2>&1
		batch_status=$?
		set -e
		if ! sha256sum -c "$execution_inventory" >/dev/null; then
			invalidate_batch 126 execution_inventory_postcheck_failed
			fail "execution inventory changed during batch: $batch_key"
		fi
		if [ "$batch_status" -ne 0 ]; then
			tail -n 80 "$batch_log" >&2 || true
			invalidate_batch "$batch_status" harness_abort
			fail "matrix batch failed: $batch_key"
		fi
	fi
	archive="$evidence_directory.closed-pending.tar.gz"
	# Recorded in the marker file so a byte-exact copy of this root verifies
	# wherever an auditor puts it. MATRIX_ID and batch_key are both restricted
	# to [A-Za-z0-9_.-], so this can never contain a path separator.
	archive_relative="evidence/auto-e2e-$run_id.closed-pending.tar.gz"
	archive_pin="$archive.sha256"
	if [ ! -f "$archive" ] || [ ! -f "$archive_pin" ] ||
		[ ! -f "$evidence_directory/result.txt" ] ||
		[ "$(cat "$evidence_directory/result.txt")" != PASS ]; then
		invalidate_batch 126 incomplete_passing_evidence
		fail "matrix batch lacks passing evidence: $batch_key"
	fi
	if ! (
		cd "$evidence_directory"
		sha256sum -c evidence-manifest.sha256 >/dev/null
	); then
		invalidate_batch 126 evidence_manifest_verification_failed
		fail "matrix batch evidence manifest failed: $batch_key"
	fi
	archive_digest=$(sha256sum "$archive" | awk '{ print $1 }')
	pinned_digest=$(awk '{ print $1 }' "$archive_pin")
	if [ "$archive_digest" != "$pinned_digest" ]; then
		invalidate_batch 126 archive_pin_mismatch
		fail "matrix batch archive pin mismatch: $batch_key"
	fi
	measurement_count=$(wc -l \
		<"$evidence_directory/attempts.jsonl" |
		tr -d '[:space:]')
	if [ "$measurement_count" -ne "$current_attempts" ]; then
		invalidate_batch 126 incomplete_measurement_denominator
		fail "matrix batch measurement count mismatch: $batch_key"
	fi
	finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	anchor_request_digest=
	anchor_receipt_one=
	anchor_receipt_two=
	if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
		if [ "$current_attempts" -ne 100 ]; then
			invalidate_anchor anchor_batch_denominator_not_100
			fail "anchored batch must contain exactly 100 attempts"
		fi
		evidence_manifest_digest=$(
			sha256sum "$evidence_directory/evidence-manifest.sha256" |
				awk '{ print $1 }'
		)
		attempt_log_digest=$(
			sha256sum "$evidence_directory/attempts.jsonl" |
				awk '{ print $1 }'
		)
		attempt_anchor_digest=$(
			sha256sum "$evidence_directory/attempts.jsonl.anchor" |
				awk '{ print $1 }'
		)
		schedule_row_digest=$(
			printf '%06d\t%s\t%s\t%s\t%s\t%s\n' \
				"$block_index" "$order_digest" "$batch_key" \
				"$profile" "$readiness" "$current_attempts" |
				sha256sum |
				awk '{ print $1 }'
		)
		anchor_request_candidate="$anchor_root/$anchor_slot.request.candidate.json"
		"$JQ_BIN" -cn \
			--arg schema "winn-phase1-archive-pin/v1" \
			--arg kind batch \
			--arg matrix "$MATRIX_ID" \
			--arg source "$EXPECTED_SOURCE_DIGEST" \
			--arg artifact "$auto_artifact_sha256" \
			--arg profileDigest "$EXPECTED_PROFILE_SHA256" \
			--arg schedule "$schedule_sha256" \
			--argjson expected "$expected_batch_count" \
			--argjson ordinal "$sequence" \
			--arg batchKey "$batch_key" \
			--arg rowDigest "$schedule_row_digest" \
			--arg profile "$profile" \
			--arg readiness "$readiness" \
			--arg archive "$archive_digest" \
			--arg evidence "$evidence_manifest_digest" \
			--arg attempts "$attempt_log_digest" \
			--arg attemptAnchor "$attempt_anchor_digest" \
			'{schema:$schema,kind:$kind,matrix_id:$matrix,
			  source_digest:$source,auto_artifact_digest:$artifact,
			  profile_digest:$profileDigest,schedule_digest:$schedule,
			  expected_batch_count:$expected,ordinal:$ordinal,
			  batch_key:$batchKey,schedule_row_digest:$rowDigest,
			  profile:$profile,readiness:$readiness,attempt_count:100,
			  archive_sha256:$archive,
			  evidence_manifest_sha256:$evidence,
			  attempt_log_sha256:$attempts,
			  attempt_anchor_sha256:$attemptAnchor}' \
			>"$anchor_request_candidate"
		if [ -z "$anchor_resume_directory" ]; then
			mkdir -m 0700 "$anchor_pending_directory"
			{
				echo "schema=winn-phase1-anchor-batch-meta/v1"
				echo "batch_key=$batch_key"
				echo "ordinal=$sequence"
				echo "started_at_utc=$started_at"
				echo "finished_at_utc=$finished_at"
			} >"$anchor_pending_directory/batch-meta.env"
			chmod 0600 "$anchor_pending_directory/batch-meta.env"
			anchor_resume_directory=$anchor_pending_directory
		fi
		anchor_pin_or_pause \
			"$anchor_resume_directory" "$anchor_request_candidate" \
			"$anchor_previous_one" "$anchor_previous_two"
		rm -f "$anchor_request_candidate"
		if [ "$anchor_resume_directory" = "$anchor_pending_directory" ]; then
			mv "$anchor_pending_directory" "$anchor_committed_directory"
		fi
		anchor_request_digest=$(
			tr -d '[:space:]' \
				<"$anchor_committed_directory/request.json.sha256"
		)
		anchor_receipt_one=$(
			tr -d '[:space:]' \
				<"$anchor_committed_directory/provider-one.receipt.json.sha256"
		)
		anchor_receipt_two=$(
			tr -d '[:space:]' \
				<"$anchor_committed_directory/provider-two.receipt.json.sha256"
		)
		anchor_previous_one=$anchor_receipt_one
		anchor_previous_two=$anchor_receipt_two
	fi
	done_temporary="$done_file.tmp"
	{
		echo "schema=winn-phase1-auto-matrix-batch-closed-pending/v3"
		echo "batch_key=$batch_key"
		echo "randomized_block=$block_index"
		echo "order_digest=$order_digest"
		echo "profile=$profile"
		echo "readiness=$readiness"
		echo "attempts=$current_attempts"
		echo "started_at_utc=$started_at"
		echo "finished_at_utc=$finished_at"
		echo "archive=$archive"
		echo "archive_relative=$archive_relative"
		echo "archive_sha256=$archive_digest"
		echo "execution_inventory_sha256=$execution_inventory_sha256"
		echo "anchor_mode=$ANCHOR_MODE"
		echo "anchor_request_sha256=$anchor_request_digest"
		echo "anchor_provider_one_receipt_sha256=$anchor_receipt_one"
		echo "anchor_provider_two_receipt_sha256=$anchor_receipt_two"
	} >"$done_temporary"
	mv "$done_temporary" "$done_file"
	completed_total=$((completed_total + current_attempts))
	echo "MATRIX_PROGRESS profile=$profile readiness=$readiness block=$block_index total=$completed_total/$expected_total"
done
exec 8<&-

terminal_aggregate_sha256=
anchor_seal_one=
anchor_seal_two=
if [ "$ANCHOR_MODE" = dual-provider-v1 ]; then
	aggregate_candidate="$anchor_root/terminal-aggregate.list.candidate"
	: >"$aggregate_candidate"
	aggregate_count=0
	for anchor_directory in "$anchor_committed_root"/[0-9]*-*; do
		anchor_name=$(basename "$anchor_directory")
		case "$anchor_name" in
			000000-genesis) continue ;;
			*-terminal-seal) continue ;;
		esac
		anchor_sequence=${anchor_name%%-*}
		anchor_batch_key=${anchor_name#*-}
		anchor_done="$MATRIX_ROOT/batches/$anchor_batch_key.closed-pending"
		if [ ! -f "$anchor_done" ]; then
			invalidate_anchor terminal_aggregate_missing_done
			fail "terminal aggregate lacks completed batch"
		fi
		anchor_request_digest=$(
			tr -d '[:space:]' \
				<"$anchor_directory/request.json.sha256"
		)
		anchor_done_digest=$(
			sha256sum "$anchor_done" | awk '{ print $1 }'
		)
		printf '%s\t%s\t%s\t%s\t%s\n' \
			"$anchor_sequence" \
			"$anchor_request_digest" \
			"$(
				tr -d '[:space:]' \
					<"$anchor_directory/provider-one.receipt.json.sha256"
			)" \
			"$(
				tr -d '[:space:]' \
					<"$anchor_directory/provider-two.receipt.json.sha256"
			)" \
			"$anchor_done_digest" \
			>>"$aggregate_candidate"
		aggregate_count=$((aggregate_count + 1))
	done
	if [ "$aggregate_count" -ne "$expected_batch_count" ]; then
		invalidate_anchor terminal_aggregate_batch_count_mismatch
		fail "terminal aggregate batch count mismatch"
	fi
	aggregate_file="$anchor_root/terminal-aggregate.list"
	if [ -f "$aggregate_file" ]; then
		cmp -s "$aggregate_candidate" "$aggregate_file" ||
			fail "terminal aggregate changed"
		rm -f "$aggregate_candidate"
	else
		mv "$aggregate_candidate" "$aggregate_file"
		chmod 0600 "$aggregate_file"
	fi
	terminal_aggregate_sha256=$(
		sha256sum "$aggregate_file" | awk '{ print $1 }'
	)
	seal_sequence=$((expected_batch_count + 1))
	seal_slot=$(printf '%06d-terminal-seal' "$seal_sequence")
	seal_request="$anchor_root/terminal-seal-request.json"
	seal_candidate="$anchor_root/terminal-seal-request.json.candidate"
	"$JQ_BIN" -cn \
		--arg schema "winn-phase1-archive-pin/v1" \
		--arg kind seal \
		--arg matrix "$MATRIX_ID" \
		--arg source "$EXPECTED_SOURCE_DIGEST" \
		--arg artifact "$auto_artifact_sha256" \
		--arg profile "$EXPECTED_PROFILE_SHA256" \
		--arg schedule "$schedule_sha256" \
		--argjson expected "$expected_batch_count" \
		--argjson ordinal "$seal_sequence" \
		--arg aggregate "$terminal_aggregate_sha256" \
		'{schema:$schema,kind:$kind,matrix_id:$matrix,
		  source_digest:$source,auto_artifact_digest:$artifact,
		  profile_digest:$profile,schedule_digest:$schedule,
		  expected_batch_count:$expected,ordinal:$ordinal,
		  aggregate_sha256:$aggregate}' \
		>"$seal_candidate"
	if [ -f "$seal_request" ]; then
		cmp -s "$seal_candidate" "$seal_request" ||
			fail "terminal seal request changed"
		rm -f "$seal_candidate"
	else
		mv "$seal_candidate" "$seal_request"
		chmod 0600 "$seal_request"
	fi
	seal_pending="$anchor_pending_root/$seal_slot.pin-pending"
	seal_committed="$anchor_committed_root/$seal_slot"
	if [ ! -d "$seal_committed" ]; then
		mkdir -m 0700 -p "$seal_pending"
		anchor_pin_or_pause \
			"$seal_pending" "$seal_request" \
			"$anchor_previous_one" "$anchor_previous_two"
		mv "$seal_pending" "$seal_committed"
	fi
	anchor_seal_one=$(
		tr -d '[:space:]' \
			<"$seal_committed/provider-one.receipt.json.sha256"
	)
	anchor_seal_two=$(
		tr -d '[:space:]' \
			<"$seal_committed/provider-two.receipt.json.sha256"
	)
	if find "$anchor_pending_root" -mindepth 1 -print -quit |
		grep -q .; then
		invalidate_anchor uncommitted_anchor_pending_state
		fail "terminal completion has uncommitted anchor state"
	fi
fi

# AUDIT-CLOSE. The producer's closing assertion about itself: under the
# deferred mode, not one anchor artifact may exist here. Every block that could
# create one is gated on the immediate mode, which is refused at the top of this
# file — so this cannot fail today, and that is exactly why it is worth
# asserting. It is the property the controller independently re-checks before it
# anchors anything, and a future edit that reintroduced producer-side anchoring
# would be caught here rather than discovered by the controller trusting a state
# that had quietly stopped holding.
if [ "$ANCHOR_MODE" = controller-deferred-dual-provider-v1 ]; then
	if [ -e "$MATRIX_ROOT/anchors" ]; then
		fail "AUDIT-CLOSE: anchor artifacts exist under a deferred-anchor run"
	fi
	for stray in "$MATRIX_ROOT"/*.receipt.json "$MATRIX_ROOT"/*-request.json; do
		if [ -e "$stray" ]; then
			fail "AUDIT-CLOSE: anchor artifact $stray exists on the producer"
		fi
	done
fi

{
	echo "schema=winn-phase1-auto-matrix-closed-pending/v3"
	echo "matrix_id=$MATRIX_ID"
	echo "completed_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "attempts=$completed_total"
	echo "schedule_sha256=$schedule_sha256"
	echo "execution_inventory_sha256=$execution_inventory_sha256"
	echo "anchor_mode=$ANCHOR_MODE"
	echo "intended_anchor_mode=$INTENDED_ANCHOR_MODE"
	echo "partial=$ALLOW_PARTIAL_MATRIX"
	echo "terminal_aggregate_sha256=$terminal_aggregate_sha256"
	echo "anchor_provider_one_seal_sha256=$anchor_seal_one"
	echo "anchor_provider_two_seal_sha256=$anchor_seal_two"
	echo "audit_close_state=pending-controller-finalization"
} >"$MATRIX_ROOT/PRODUCER_CLOSED_PENDING.tmp"
if [ "$completed_total" -ne "$expected_total" ]; then
	fail "matrix completed $completed_total attempts, want $expected_total"
fi
# AUDIT-CLOSE. Deliberately NOT "COMPLETE". This root's trails are final and
# its manifests are sealed, and not one of them has been closed by a terminal
# checkpoint yet, so it is not complete in any sense a consumer should act on.
# The controller writes COMPLETE after it has closed and verified every batch.
mv "$MATRIX_ROOT/PRODUCER_CLOSED_PENDING.tmp" \
	"$MATRIX_ROOT/PRODUCER_CLOSED_PENDING"
echo "MATRIX_CLOSED_PENDING id=$MATRIX_ID attempts=$completed_total \
root=$MATRIX_ROOT audit_close=pending-controller-finalization"
