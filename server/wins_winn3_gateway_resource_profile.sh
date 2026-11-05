#!/usr/bin/env bash
# Pure profile consumer. Stdin is JSON; arguments are expected N, MTU, and
# already-canonical comma-separated plan. This never acquires a target profile.
validate_gateway_resource_profile_json() {
  if [[ "$#" -ne 3 ]]; then
    printf '%s\n' '[winn3-gw][ERR] resource profile requires expected sessions, MTU and canonical plan.' >&2
    return 1
  fi
  command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' '[winn3-gw][ERR] python3 is required to validate a resource profile.' >&2
    return 1
  }
  # Preserve the caller's profile stream before the heredoc supplies Python code.
  # Isolation disables environment imports and site hooks; no bytecode is written.
  python3 -I -S -B - "$1" "$2" "$3" 3<&0 <<'PYEOF'
import json
import os
import re
import sys

MAX_INPUT_BYTES = 16384
MAX_INTEGER = (1 << 63) - 1
NUMERIC_FIELDS = (
    "schema_version", "max_sessions", "path_mtu", "message_bytes",
    "inner_payload_bytes", "send_queue_packets", "send_buffer_slab_bytes",
    "pipe_inbox_packets", "pipe_buffer_slab_bytes", "demux_buffer_bytes",
    "demux_packets_per_side", "demux_sides", "batch_receive_slots",
    "send_payload_backing_per_session_bytes", "pipe_payload_backing_per_session_bytes",
    "shared_demux_admitted_backing_bytes", "shared_demux_staging_backing_bytes",
    "configured_queue_payload_backing_bytes",
)
FIELDS = set(NUMERIC_FIELDS) | {"migration_plan", "accounting_scope", "not_included"}
EXCLUSIONS = [
    "queue_and_packet_metadata", "runtime_gc_and_pool_retention",
    "session_device_cover_and_kernel_storage",
    "non_demux_in_flight_producer_and_consumer_buffers",
    "retained_and_temporary_send_receive_and_parser_batch_storage",
    "future_lifetime_ceiling_widening",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive_integer(text):
    require(re.fullmatch(r"[1-9][0-9]*", text) is not None,
            "numeric values must be positive decimal integers")
    require(len(text) <= 19, "integer exceeds signed 64-bit range")
    value = int(text)
    require(value <= MAX_INTEGER, "integer exceeds signed 64-bit range")
    return value


def reject_noninteger(_text):
    raise ValueError("floating-point and nonfinite values are not supported")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def validate_plan(plan):
    require(type(plan) is list and 1 <= len(plan) <= 3,
            "migration plan must be a nonempty canonical array")
    require(all(type(item) is str and item in ("udp", "tcp", "tls") for item in plan),
            "migration plan contains a noncanonical entry")
    require(len(set(plan)) == len(plan), "migration plan contains a duplicate entry")


def product(*values):
    total = 1
    for value in values:
        require(total <= MAX_INTEGER // value, "resource product exceeds signed 64-bit range")
        total *= value
    return total


def add(*values):
    total = 0
    for value in values:
        require(total <= MAX_INTEGER - value, "resource sum exceeds signed 64-bit range")
        total += value
    return total


def validate():
    expected_n = positive_integer(sys.argv[1])
    expected_mtu = positive_integer(sys.argv[2])
    expected_plan = sys.argv[3].split(",")
    validate_plan(expected_plan)
    with os.fdopen(3, "rb", closefd=True) as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    require(len(raw) <= MAX_INPUT_BYTES, "resource profile exceeds 16384 bytes")
    profile = json.loads(raw.decode("utf-8", errors="strict"),
                         object_pairs_hook=unique_object,
                         parse_int=positive_integer,
                         parse_float=reject_noninteger,
                         parse_constant=reject_noninteger)
    require(type(profile) is dict and set(profile) == FIELDS,
            "resource profile must contain exactly the version-one fields")
    for name in NUMERIC_FIELDS:
        require(type(profile[name]) is int and 1 <= profile[name] <= MAX_INTEGER,
                "resource numeric field is not a positive signed-64 integer")
    require(profile["schema_version"] == 1, "unsupported resource profile schema")
    require(profile["accounting_scope"] == "queue_payload_backing_only",
            "unrecognized resource accounting scope")
    require(profile["not_included"] == EXCLUSIONS,
            "resource exclusions differ from the version-one contract")
    validate_plan(profile["migration_plan"])
    require((profile["max_sessions"], profile["path_mtu"], profile["migration_plan"])
            == (expected_n, expected_mtu, expected_plan),
            "resource profile does not match expected sessions, MTU and plan")
    require(profile["inner_payload_bytes"] < profile["message_bytes"] <= profile["path_mtu"],
            "resource payload sizing is inconsistent")
    require(profile["demux_buffer_bytes"] == max(4096, profile["message_bytes"]),
            "demux capacity differs from the version-one sizing contract")
    send = product(profile["send_queue_packets"],
                   max(profile["send_buffer_slab_bytes"], profile["inner_payload_bytes"]))
    pipe = product(profile["pipe_inbox_packets"],
                   max(profile["pipe_buffer_slab_bytes"], profile["message_bytes"]))
    admitted = product(profile["demux_sides"], profile["demux_packets_per_side"],
                       profile["demux_buffer_bytes"])
    # This is the maximum batch-path staging allowance, even on scalar fallback.
    staging = product(profile["batch_receive_slots"], profile["demux_buffer_bytes"])
    total = add(product(profile["max_sessions"], add(send, pipe)), admitted, staging)
    expected_totals = {
        "send_payload_backing_per_session_bytes": send,
        "pipe_payload_backing_per_session_bytes": pipe,
        "shared_demux_admitted_backing_bytes": admitted,
        "shared_demux_staging_backing_bytes": staging,
        "configured_queue_payload_backing_bytes": total,
    }
    require(all(profile[name] == value for name, value in expected_totals.items()),
            "resource subtotal or total does not match its accounting identity")
    return json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


try:
    normalized = validate()
except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
    # Do not echo untrusted input or parser excerpts into deployment logs.
    sys.stderr.write("[winn3-gw][ERR] invalid or inconsistent resource profile.\n")
    sys.exit(1)
sys.stdout.write(normalized)
PYEOF
}
