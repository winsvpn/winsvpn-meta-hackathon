"""Exercise current hub authority with real SQLite and local signing only."""
from pathlib import Path
import asyncio
import base64
import json
import logging
import os
import shutil
import sys
from unittest.mock import patch

ROOT = Path.cwd()
OUT = ROOT / "docs/evidence/round12_remediation"
sys.path.insert(0, str(ROOT / "server"))
import test_account_deletion_hub as harness
import test_winn3_descriptor_hub as descriptor

CANDIDATE = True
harness._install_stubs = lambda: None


def guard(event, args):
    if event == "socket.connect":
        raise PermissionError("No network in state probe")
    if event == "subprocess.Popen" and Path(str(args[0])).name != "openssl":
        raise PermissionError("Only local OpenSSL fixture operations are permitted")


sys.addaudithook(guard)


def load():
    def close_handlers(**kwargs):
        for handler in kwargs.get("handlers", []):
            handler.close()
    with patch("logging.basicConfig", side_effect=close_handlers):
        module = descriptor.load_hub_with_ring(
            WINN3_INNER_POOL_CIDR="10.10.0.0/24", WINN3_CANARY_NODE_SLUG="",
            DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0,
            HIDE_CONTROL_ORIGIN=0,
        )
    module.logger.propagate = False
    module.logger.addHandler(logging.NullHandler())
    module.security_alert = lambda *args, **kwargs: None
    module.send_account_email = lambda *args, **kwargs: False
    module.sync_peer_to_node = lambda *args, **kwargs: True
    harness.seed_account(module, devices=0)
    for slug in ("lab-alpha", "lab-beta"):
        host = descriptor.NODE_HOST if slug == "lab-alpha" else "203.0.113.9"
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=slug, endpoint=host + ":51820"))
        descriptor.seed_node(module, slug=slug, endpoint=host + ":9110", protocol_version="winn/3",
                             protocol_params_json="{}",
                             descriptor_json=json.dumps({"payload": payload, "sig": signature}))
        with module.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host=? WHERE slug=?", (host, slug))
    module.DEVICE_LIMIT = 1
    publications = []
    module.sync_winn3_registry_to_node = lambda conn, host, slug: (
        publications.append((slug, module.winn3_peer_registry_document(conn, slug))) or True
    )
    module.publications = publications
    return module


def login(module, suffix, location="lab-alpha", key_byte=b"C"):
    return descriptor.build_login(
        module, supports_winn3=True, supports_winn3_descriptor=True,
        device_id="audit-device-" + suffix, device_fingerprint="audit-fingerprint-" + suffix,
        device_model="audit-harness", location=location,
        client_public_key=base64.b64encode(key_byte * 32).decode(),
    )


def activate(module):
    with module.get_db() as conn:
        return module.issue_activation_secret(conn, harness.ACCOUNT)


def request(module, model, activation=None, bearer=None):
    import httpx
    headers = {}
    if activation:
        headers["x-wins-activation"] = activation
    if bearer:
        headers["authorization"] = "Bearer " + bearer
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url="https://audit.invalid") as client:
            response = await client.post("/verify", headers=headers, json=model.model_dump())
            return response.status_code, response.json()
    async def parked_background_tasks(self):
        return None
    with patch("starlette.background.BackgroundTasks.__call__", new=parked_background_tasks):
        return asyncio.run(exercise())

