#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import gcp_proof_deploy as deploy
import gcp_proof_fleet as fleet
import gcp_proof_live_probe as live_probe
import gcp_proof_remote_action as remote_action


ROOT = Path(__file__).resolve().parents[1]
FLEET_ID = "123456789abc"
ROLE_ZONES = {
    "control": "us-central1-a",
    "data-winn3": "us-central1-b",
    "data-cover": "us-central1-c",
}


def expected_contract() -> dict[str, object]:
    return {
        "network": f"pf-{FLEET_ID}-net",
        "subnets": [
            {
                "name": f"pf-{FLEET_ID}-sn-control",
                "region": "us-central1",
                "role": "control",
            },
            {
                "name": f"pf-{FLEET_ID}-sn-data-winn3",
                "region": "us-central1",
                "role": "data-winn3",
            },
            {
                "name": f"pf-{FLEET_ID}-sn-data-cover",
                "region": "us-central1",
                "role": "data-cover",
            },
        ],
        "firewalls": {
            "admin_ssh": f"pf-{FLEET_ID}-admin-ssh",
            "control_http": f"pf-{FLEET_ID}-control-http",
            "winn3_ingress": f"pf-{FLEET_ID}-winn3-in",
            "cover_ingress": f"pf-{FLEET_ID}-cover-in",
        },
    }


def test_planner_deploy_remote_and_live_probe_share_exact_resource_names() -> None:
    canonical = fleet.canonical_resource_contract(FLEET_ID, ROLE_ZONES)
    assert canonical == expected_contract()

    instances = {
        role: {"instance": f"proof-{role}", "zone": zone}
        for role, zone in ROLE_ZONES.items()
    }
    deploy_names = deploy._proof_resource_names(FLEET_ID, instances)
    assert deploy_names == {
        "network": canonical["network"],
        "subnets": [
            {"name": row["name"], "region": row["region"]}
            for row in canonical["subnets"]
        ],
        "firewalls": list(canonical["firewalls"].values()),
    }

    binding = {
        "fleet_id": FLEET_ID,
        **{
            role: {"instance": f"proof-{role}", "zone": zone}
            for role, zone in ROLE_ZONES.items()
        },
    }
    remote_names = remote_action.resource_identity(binding)
    assert remote_names["network"] == canonical["network"]
    assert remote_names["subnets"] == [row["name"] for row in canonical["subnets"]]
    assert remote_names["firewalls"] == sorted(canonical["firewalls"].values())

    args = SimpleNamespace(
        fleet_id=FLEET_ID,
        network=canonical["network"],
        control_instance="proof-control",
        control_zone=ROLE_ZONES["control"],
        control_machine_type="e2-standard-2",
        control_subnet=canonical["subnets"][0]["name"],
        winn3_data_instance="proof-data-winn3",
        winn3_data_zone=ROLE_ZONES["data-winn3"],
        winn3_data_machine_type="e2-standard-2",
        winn3_data_subnet=canonical["subnets"][1]["name"],
        cover_data_instance="proof-data-cover",
        cover_data_zone=ROLE_ZONES["data-cover"],
        cover_data_machine_type="e2-standard-2",
        cover_data_subnet=canonical["subnets"][2]["name"],
    )
    assert live_probe._canonical_resources(args) == canonical


def test_live_probe_rejects_every_resource_name_split_without_network_access() -> None:
    canonical = expected_contract()
    base = {
        "fleet_id": FLEET_ID,
        "network": canonical["network"],
        "control_instance": "proof-control",
        "control_zone": ROLE_ZONES["control"],
        "control_machine_type": "e2-standard-2",
        "control_subnet": canonical["subnets"][0]["name"],
        "winn3_data_instance": "proof-data-winn3",
        "winn3_data_zone": ROLE_ZONES["data-winn3"],
        "winn3_data_machine_type": "e2-standard-2",
        "winn3_data_subnet": canonical["subnets"][1]["name"],
        "cover_data_instance": "proof-data-cover",
        "cover_data_zone": ROLE_ZONES["data-cover"],
        "cover_data_machine_type": "e2-standard-2",
        "cover_data_subnet": canonical["subnets"][2]["name"],
    }
    for key, value in (
        ("network", f"pf-{FLEET_ID}-other"),
        ("control_subnet", f"pf-{FLEET_ID}-sn-0"),
        ("winn3_data_subnet", f"pf-{FLEET_ID}-sn-1"),
        ("cover_data_subnet", f"pf-{FLEET_ID}-sn-2"),
    ):
        mutated = dict(base)
        mutated[key] = value
        try:
            live_probe._canonical_resources(SimpleNamespace(**mutated))
        except fleet.FleetRefused as exc:
            assert "canonical fleet contract" in str(exc)
        else:
            raise AssertionError(f"resource split was accepted for {key}")


def test_role_file_payloads_and_installers_use_only_canonical_roles() -> None:
    assert fleet.ROLE_FILE_PAYLOADS == {
        "control": b"control\n",
        "data-winn3": b"data-winn3\n",
        "data-cover": b"data-cover\n",
    }
    cover = (ROOT / "server/wins_data_plane_setup_ONETOUCH.sh").read_text(
        encoding="utf-8"
    )
    # Slice S6: the real server/wins_winn3_gateway_install.sh is a tombstone.
    # The data-winn3 role is defined by the standalone installer, so this
    # contract reads the frozen copy of it (deleted with the tombstone).
    winn3 = (ROOT / "server/testdata/winn3_gateway_install_retired/wins_winn3_gateway_install.sh.snapshot").read_text(
        encoding="utf-8"
    )
    assert "printf 'data-cover\\n' > /etc/winsvpn/role" in cover
    assert '!= "data-cover"' in cover
    assert "printf 'data-winn3\\n' > /etc/winsvpn/role" in winn3
    assert '"${role}" != "data-winn3"' in winn3
    assert '"${MODE}" != "install"' in winn3
    assert "printf 'data\\n' > /etc/winsvpn/role" not in cover
    assert "printf 'winn3\\n' > /etc/winsvpn/role" not in winn3


def test_remote_observer_sudo_vector_is_fixed_and_not_parser_controlled() -> None:
    assert live_probe.REMOTE_SUDO_ARGV == ("/usr/bin/sudo", "--non-interactive")
    assert all("sudo" not in action.dest for action in live_probe.parser()._actions)

