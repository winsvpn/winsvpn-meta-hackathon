#!/usr/bin/env bash
set -Eeuo pipefail

echo "Deprecated: performance, sysctl, encryption, and swap policy is generated" >&2
echo "by the authoritative server role installer. Run the applicable" >&2
echo "server/wins_*_setup_ONETOUCH.sh --preflight, then --deploy." >&2
exit 2
