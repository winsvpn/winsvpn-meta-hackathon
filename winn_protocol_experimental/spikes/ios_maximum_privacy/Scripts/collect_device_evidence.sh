#!/bin/sh
set -eu

spike_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_root="$(CDPATH='' cd -- "${spike_script_dir}/.." && pwd)"
spike_device_udid="${WINN_SPIKE_DEVICE_UDID:-<DEVICE_UDID>}"
spike_timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
spike_runtime_root="${spike_root}/.runtime/device-evidence"
mkdir -p "${spike_runtime_root}"
spike_destination="$(
  printf '%s' \
    "${1:-${spike_runtime_root}/device-${spike_timestamp}}"
)"
spike_destination_parent="$(
  CDPATH='' cd -- "$(dirname -- "${spike_destination}")" && pwd
)"
case "${spike_destination_parent}/$(basename "${spike_destination}")" in
  "${spike_runtime_root}"/*) ;;
  *)
    echo "FAIL: raw collection destination must be under ${spike_runtime_root}." >&2
    exit 1
    ;;
esac

test ! -e "${spike_destination}" || {
  echo "FAIL: destination already exists: ${spike_destination}" >&2
  exit 1
}
mkdir -p "${spike_destination}"

mkdir -p \
  "${spike_destination}/host-collected" \
  "${spike_destination}/provider-runtime"

spike_copy_count=0
if xcrun devicectl device copy from \
  --device "${spike_device_udid}" \
  --user mobile \
  --domain-type appDataContainer \
  --domain-identifier org.winsvpn.experimental.wcf3privacyspike \
  --source Documents/CollectedEvidence \
  --destination "${spike_destination}/host-collected"
then
  spike_copy_count=$((spike_copy_count + 1))
fi

# Stop, failure, and crash-adjacent records may no longer be reachable through
# a live provider message. Copy the experimental App Group directly so those
# retained records are not stranded outside the advertised workflow.
if xcrun devicectl device copy from \
  --device "${spike_device_udid}" \
  --user mobile \
  --domain-type appGroupDataContainer \
  --domain-identifier group.org.winsvpn.experimental.wcf3privacyspike \
  --source Evidence/runtime \
  --destination "${spike_destination}/provider-runtime"
then
  spike_copy_count=$((spike_copy_count + 1))
fi

test "${spike_copy_count}" -gt 0 || {
  echo "FAIL: neither host nor provider evidence was reachable." >&2
  exit 1
}

spike_jsonl_count="$(
  find "${spike_destination}" -type f -name '*.jsonl' | wc -l |
    tr -d ' '
)"
spike_start_receipt_count="$(
  find "${spike_destination}" -type f -name '*.start-receipt.json' |
    wc -l |
    tr -d ' '
)"
spike_file_count="$(
  find "${spike_destination}" -type f \
    \( -name '*.jsonl' -o -name '*.stop-receipt.json' \
       -o -name '*.start-receipt.json' \) | wc -l |
    tr -d ' '
)"
test "${spike_jsonl_count}" -gt 0 || {
  echo "FAIL: no JSONL evidence was collected." >&2
  exit 1
}
test "${spike_start_receipt_count}" -gt 0 || {
  echo "FAIL: no activation receipt was collected." >&2
  exit 1
}

(
  cd "${spike_destination}"
  find . -type f \
    \( -name '*.jsonl' -o -name '*.stop-receipt.json' \
       -o -name '*.start-receipt.json' \) -print |
    LC_ALL=C sort |
    while IFS= read -r spike_evidence; do
      spike_basename="$(basename "${spike_evidence}")"
      spike_digest="$(
        shasum -a 256 "${spike_evidence}" | awk '{print $1}'
      )"
      case "${spike_evidence}" in
        ./host-collected/*) spike_origin="host-collected" ;;
        ./provider-runtime/*) spike_origin="provider-runtime" ;;
        *) spike_origin="unknown" ;;
      esac
      printf '%s\t%s\t%s\t%s\n' \
        "${spike_origin}" \
        "${spike_basename}" \
        "${spike_digest}" \
        "${spike_evidence}"
    done >INVENTORY.tsv

  awk -F '	' '
    {
      if (($2 in digest) && digest[$2] != $3) {
        printf "%s\t%s\t%s\t%s\n", $2, digest[$2], $3, $4
      } else {
        digest[$2] = $3
      }
    }
  ' INVENTORY.tsv >CONFLICTS.tsv
  test ! -s CONFLICTS.tsv || {
    echo "FAIL: host/provider copies conflict; see CONFLICTS.tsv." >&2
    exit 1
  }

  while IFS= read -r spike_jsonl; do
    spike_run_name="$(basename "${spike_jsonl}" .jsonl)"
    awk -F '	' -v expected="${spike_run_name}.start-receipt.json" \
      '$2 == expected { found = 1 } END { exit(found ? 0 : 1) }' \
      INVENTORY.tsv || {
        echo "FAIL: ${spike_jsonl} has no matching activation receipt." >&2
        exit 1
      }
  done <<EOF
$(find . -type f -name '*.jsonl' -print | LC_ALL=C sort)
EOF

  find . -type f \
    \( -name '*.jsonl' -o -name '*.stop-receipt.json' \
       -o -name '*.start-receipt.json' \) -print |
    LC_ALL=C sort |
    while IFS= read -r spike_evidence; do
      shasum -a 256 "${spike_evidence}"
    done >SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)

printf 'PASS: collected and hashed %s device evidence file(s)\n' \
  "${spike_file_count}"
printf 'destination=%s\n' "${spike_destination}"
