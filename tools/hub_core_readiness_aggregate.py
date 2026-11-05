#!/usr/bin/env python3
"""Return only aggregate, read-only Core readiness state from the Hub DB."""

from __future__ import annotations

import json
import sqlite3


def main() -> int:
    database = sqlite3.connect(
        "file:/root/vpn_auth/vpn_users.db?mode=ro", uri=True, timeout=5
    )
    database.row_factory = sqlite3.Row
    core = database.execute(
        """
        SELECT count(*) AS total,
               sum(CASE WHEN runtime_ready=1 THEN 1 ELSE 0 END) AS ready,
               sum(CASE WHEN status='online' AND management_status='ok'
                        THEN 1 ELSE 0 END) AS managed_online,
               sum(CASE WHEN runtime_checked_at >= datetime('now','-180 seconds')
                        THEN 1 ELSE 0 END) AS runtime_recent
          FROM core_servers
        """
    ).fetchone()
    assignments = database.execute(
        """
        SELECT count(*) AS total,
               sum(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
               sum(CASE WHEN status='active'
                         AND applied_revision GLOB '[0-9a-f]*'
                         AND length(applied_revision)=64
                        THEN 1 ELSE 0 END) AS revision_applied,
               sum(CASE WHEN status='active'
                         AND runtime_validated_at >= datetime('now','-180 seconds')
                        THEN 1 ELSE 0 END) AS runtime_recent
          FROM double_vpn_assignments
        """
    ).fetchone()
    eligible = database.execute(
        """
        SELECT count(*) AS total,
               sum(CASE WHEN a.applied_revision GLOB '[0-9a-f]*'
                         AND length(a.applied_revision)=64
                        THEN 1 ELSE 0 END) AS revision_applied,
               sum(CASE WHEN a.runtime_validated_at >= datetime('now','-180 seconds')
                        THEN 1 ELSE 0 END) AS runtime_recent
          FROM double_vpn_assignments a
          JOIN devices d ON d.device_id=a.device_id
                        AND d.account_number=a.account_number
          JOIN users u ON u.account_number=a.account_number
          JOIN core_exit_peers e ON e.core_id=a.core_id
                                AND e.exit_slug=a.exit_slug
          JOIN nodes n ON n.slug=a.exit_slug
         WHERE a.status='active'
           AND u.status='active'
           AND n.status NOT IN ('offline','maintenance')
           AND (u.expiration_date IS NULL OR u.expiration_date=''
                OR u.expiration_date >= datetime('now'))
        """
    ).fetchone()
    database.close()
    print(
        json.dumps(
            {
                "contract": "winsvpn-hub-core-readiness-aggregate-v1",
                "core": dict(core),
                "assignments": dict(assignments),
                "eligible_assignments": dict(eligible),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
