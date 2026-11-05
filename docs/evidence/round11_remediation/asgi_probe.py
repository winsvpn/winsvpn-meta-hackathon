"""Real ASGI and SQLite admission probes. Remote operations are local doubles."""
from contextlib import ExitStack
import json
import shutil
from unittest.mock import patch

import asgi_fixture as f


def cleanup(module):
    for handler in list(module.logger.handlers):
        handler.close()
        module.logger.removeHandler(handler)
    shutil.rmtree(module._TMPDIR)


def partial_remote_install():
    module = f.load()
    try:
        activation = f.activate(module)
        model = f.login(module, "partial-install")
        installed = set()

        def uncertain_install(host, device):
            installed.add((host, device["client_public_key"]))
            return False

        module.sync_peer_to_node = uncertain_install
        status, response = f.request(module, model, activation=activation)
        with module.get_db() as conn:
            device_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            jobs = conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0]
            used = conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0]
        assert status == 503 and device_count == 0 and used is None

        def remove(host, key):
            installed.discard((host, key))
            return True

        module.remove_peer_from_node = remove
        drained = module.drain_peer_revocation_outbox()
        result = {"http_status": status, "device_rows": device_count,
                  "activation_consumed": used is not None, "repair_jobs": jobs,
                  "remote_peer_remaining_after_drain": bool(installed), "drain": drained}
        if f.CANDIDATE:
            assert jobs == 1 and not installed
        else:
            assert jobs == 0 and installed
        return result
    finally:
        cleanup(module)


def double_core_timeout():
    module = f.load()
    try:
        with module.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1', protocol_params_json='{}'")
            conn.execute("INSERT INTO core_servers (core_id, exit_public_key, ingress_public_key, "
                         "ingress_endpoint, tunnel_gateway_ipv4, status, runtime_ready) "
                         "VALUES ('fixture-core', ?, ?, '192.0.2.50:9210', '10.9.0.1', 'online', 1)",
                         ("D" * 43 + "=", "E" * 43 + "="))
            core = dict(conn.execute("SELECT * FROM core_servers").fetchone())
        # Select a fixture core independently of deployment promotion latches.
        # The real assignment builder and real readiness poll still execute.
        module.select_double_vpn_core = lambda conn: core
        module.DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS = 0
        activation = f.activate(module)
        model = f.login(module, "core-timeout")
        model.double_vpn = True
        first, body = f.request(module, model, activation=activation)
        with module.get_db() as conn:
            used = conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0]
            rows = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            assignments = conn.execute("SELECT COUNT(*) FROM double_vpn_assignments").fetchone()[0]
        second, retry_body = f.request(module, model, activation=activation)
        result = {"first_status": first, "first_detail": body.get("detail"),
                  "retry_status": second, "retry_detail": retry_body.get("detail"),
                  "activation_consumed": used is not None, "device_rows": rows,
                  "assignment_rows": assignments, "bearer_delivered": "device_auth_token" in body}
        assert first == 503 and rows == 1 and assignments == 1
        if f.CANDIDATE:
            assert second == 503 and used is None
        else:
            assert second == 401 and used is not None
        return result
    finally:
        cleanup(module)


def double_core_terminal_cases():
    results = {}
    for scenario in ("success", "replaced_during_wait", "revoked_during_wait"):
        module = f.load()
        try:
            with module.get_db() as conn:
                conn.execute("UPDATE nodes SET protocol_version='winn/1', protocol_params_json='{}'")
                conn.execute("INSERT INTO core_servers (core_id, exit_public_key, ingress_public_key, "
                             "ingress_endpoint, tunnel_gateway_ipv4, status, runtime_ready) "
                             "VALUES ('fixture-core', ?, ?, '192.0.2.50:9210', '10.9.0.1', 'online', 1)",
                             ("D" * 43 + "=", "E" * 43 + "="))
                core = dict(conn.execute("SELECT * FROM core_servers").fetchone())
            module.select_double_vpn_core = lambda conn: core

            def acknowledge(core_id, device_id, revision):
                with module.get_db() as conn:
                    conn.execute("UPDATE double_vpn_assignments SET applied_revision=?, runtime_validated_at=? "
                                 "WHERE device_id=?", (revision, module.utcnow().isoformat(), device_id))
                    if scenario == "replaced_during_wait":
                        conn.execute("UPDATE devices SET device_auth_token_hash=? WHERE device_id=?",
                                     (module.token_digest("fixture-replacement-bearer"), device_id))
                    elif scenario == "revoked_during_wait":
                        conn.execute("UPDATE users SET status='expired'")
                return True

            module._wait_for_core_assignment_ready_sync = acknowledge
            activation = f.activate(module)
            model = f.login(module, "terminal-" + scenario)
            model.double_vpn = True
            status, body = f.request(module, model, activation=activation)
            with module.get_db() as conn:
                used = conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0]
                saved = conn.execute("SELECT device_auth_token_hash FROM devices").fetchone()[0]
            delivered = body.get("device_auth_token")
            result = {"status": status, "bearer_delivered": bool(delivered),
                      "bearer_matches_current": bool(delivered and module.token_digest(delivered) == saved),
                      "activation_consumed": used is not None}
            if scenario == "success":
                assert status == 200 and result["bearer_matches_current"] and used is not None
                replay, _ = f.request(module, model, activation=activation)
                assert replay == 401
                result["activation_replay_status"] = replay
            elif f.CANDIDATE:
                assert status == 409 and not delivered and used is None
            else:
                assert status == 200 and delivered
            results[scenario] = result
        finally:
            cleanup(module)
    return results


results = {"candidate": f.CANDIDATE,
           "partial_remote_install": partial_remote_install(),
           "double_core_timeout": double_core_timeout(),
           "double_core_terminal_cases": double_core_terminal_cases()}
(f.OUT / ("asgi-results.json")).write_text(
    json.dumps(results, indent=2) + "\n")
print(json.dumps(results, indent=2))
