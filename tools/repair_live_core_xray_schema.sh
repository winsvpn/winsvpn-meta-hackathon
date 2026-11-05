#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || {
  echo "Run this repair with sudo." >&2
  exit 1
}

agent=/usr/local/bin/wins-core-sync
old='settings:{allowedNetwork:"udp",rewriteAddress:"127.0.0.1",rewritePort:$remote_awg_port,followRedirect:false,userLevel:0}'
new='settings:{network:"udp",address:"127.0.0.1",port:$remote_awg_port,followRedirect:false,userLevel:0}'

[[ -f "${agent}" ]] || {
  echo "Core sync agent is missing: ${agent}" >&2
  exit 1
}

state="$(python3 - "${agent}" "${old}" "${new}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old, new = sys.argv[2:]
source = path.read_text(encoding="utf-8")
old_count = source.count(old)
new_count = source.count(new)
if old_count == 1 and new_count == 0:
    print("repair")
elif old_count == 0 and new_count == 1:
    print("current")
else:
    raise SystemExit(
        f"Refusing ambiguous live repair: old_count={old_count} new_count={new_count}"
    )
PY
)"

if [[ "${state}" == "repair" ]]; then
  backup="${agent}.pre-xray-udp-$(date -u +%Y%m%dT%H%M%SZ).bak"
  cp -a -- "${agent}" "${backup}"
  tmp="$(mktemp /usr/local/bin/.wins-core-sync.XXXXXX)"
  python3 - "${agent}" "${tmp}" "${old}" "${new}" <<'PY'
from pathlib import Path
import sys

source_path, destination_path, old, new = sys.argv[1:]
source = Path(source_path).read_text(encoding="utf-8")
if source.count(old) != 1:
    raise SystemExit("The expected pinned-Xray schema occurs an unexpected number of times")
Path(destination_path).write_text(source.replace(old, new), encoding="utf-8")
PY
  chown root:root "${tmp}"
  chmod 0700 "${tmp}"
  bash -n "${tmp}"
  mv -f -- "${tmp}" "${agent}"
fi

systemctl start wins-core-sync.service
systemctl is-failed --quiet wins-core-sync.service && {
  systemctl status wins-core-sync.service --no-pager -n 60
  exit 1
}

python3 - <<'PY'
import json
from pathlib import Path

configs = sorted(Path("/usr/local/etc/xray/core-exits").glob("corex*.json"))
if not configs:
    raise SystemExit("No Core exit Xray configuration was generated")
for path in configs:
    config = json.loads(path.read_text(encoding="utf-8"))
    inbound = next(
        item for item in config.get("inbounds", [])
        if item.get("tag") == "awg-local-in"
    )
    settings = inbound.get("settings") or {}
    if settings.get("network") != "udp":
        raise SystemExit(f"{path.name} is not using the pinned Xray UDP schema")
    if any(key in settings for key in ("allowedNetwork", "rewriteAddress", "rewritePort")):
        raise SystemExit(f"{path.name} still contains prerelease Xray fields")
    print(f"{path.name}: UDP listener {inbound.get('port')}")
PY

while read -r port; do
  [[ -n "${port}" ]] || continue
  ss -Hlun | awk -v suffix=":${port}" '{for (i = 1; i <= NF; i++) if ($i ~ (suffix "$")) found=1} END {exit !found}' || {
    echo "Expected UDP listener is missing on port ${port}." >&2
    exit 1
  }
  if ss -Hlnt | awk -v suffix=":${port}" '{for (i = 1; i <= NF; i++) if ($i ~ (suffix "$")) found=1} END {exit !found}'; then
    echo "Unexpected TCP listener remains on port ${port}." >&2
    exit 1
  fi
done < <(python3 - <<'PY'
import json
from pathlib import Path
for path in sorted(Path("/usr/local/etc/xray/core-exits").glob("corex*.json")):
    config = json.loads(path.read_text(encoding="utf-8"))
    for inbound in config.get("inbounds", []):
        if inbound.get("tag") == "awg-local-in":
            print(inbound["port"])
PY
)

echo LIVE_CORE_XRAY_SCHEMA_REPAIR=PASS
