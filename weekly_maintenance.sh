#!/usr/bin/env bash
set -Eeuo pipefail

echo "Deprecated: role-specific no-removal maintenance is installed by the" >&2
echo "authoritative one-touch installer. On a deployed host, inspect:" >&2
echo "  systemctl status wins-weekly-maintenance.timer" >&2
exit 2
