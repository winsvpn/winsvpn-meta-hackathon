#!/usr/bin/env python3
"""Summarize recent Suricata alerts without emitting addresses or payloads."""

from __future__ import annotations

import collections
import datetime as dt
import json
import os
import pathlib


def main() -> int:
    minutes = max(1, min(60, int(os.getenv("WINS_ALERT_WINDOW_MINUTES", "60"))))
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)
    path = pathlib.Path("/var/log/suricata/eve.json")
    if not path.is_file() or path.is_symlink():
        print(json.dumps({"ok": False, "error_type": "eve_unavailable"}, separators=(",", ":")))
        return 1
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - 16 * 1024 * 1024))
        if handle.tell():
            handle.readline()
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    summary: collections.Counter[tuple[object, ...]] = collections.Counter()
    for line in lines:
        try:
            item = json.loads(line)
            if item.get("event_type") != "alert":
                continue
            timestamp = dt.datetime.fromisoformat(str(item.get("timestamp") or "").replace("Z", "+00:00"))
            if timestamp.astimezone(dt.timezone.utc) < cutoff:
                continue
            alert = item.get("alert") or {}
            summary[(
                int(alert.get("signature_id") or 0),
                str(alert.get("action") or "unknown").lower(),
                str(alert.get("signature") or "")[:160],
                str(alert.get("category") or "")[:120],
                int(alert.get("severity") or 0),
                str(item.get("proto") or "").upper()[:12],
                int(item.get("dest_port") or 0),
            )] += 1
        except Exception:
            continue
    alerts = [
        {
            "sid": key[0], "action": key[1], "message": key[2],
            "category": key[3], "severity": key[4], "protocol": key[5],
            "destination_port": key[6], "count": count,
        }
        for key, count in sorted(summary.items())
    ]
    print(json.dumps({
        "ok": True,
        "role": os.getenv("WINS_PROBE_ROLE_OVERRIDE", "data"),
        "contract": "winsvpn-recent-suricata-alert-summary-v1",
        "window_minutes": minutes,
        "alerts": alerts,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
