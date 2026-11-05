#!/usr/bin/env python3
"""Execute only the authenticated WinsVPN GCP proof deployment sequence.

The fleet planner remains responsible for creating resources.  This executor
does not accept caller-authored commands: it transfers an exact manifest-only
bundle, invokes the reviewed remote helper through fixed gcloud argv vectors,
runs the eight reviewed installer steps in their one valid order, then drives
the helper's control/data authenticated key exchange v1 primitives. Secret
material moves only through an authenticated SSH pipe onto helper stdin/stdout
and is never placed on argv, logs, or receipts.

Before any SCP, SSH, or other remote mutation, every target must present a live
`gcloud compute instances describe` result from the same custody runner.  That
result has to prove a newly created proof VM bound to the exact fleet, role,
creation transaction, labels, project, zone, machine identity, and clean
deployment state.  Existing, reused, mislabeled, or partially deployed VMs are
refused.  Every authenticated failure rolls back exact uploaded files, extracted
trees, and partial services, then inspects bounded local residuals.  It deletes
only the proven proof resources when cleanup is separately authorized, and
authorized deletion is not success until exact-name describes prove each VM,
firewall, subnet, and network is absent.  Cleanup does not require an
acceptance receipt, performs no cloud mutation without that explicit flag, and
never converts a cleanup failure into a passing result.
"""

from __future__ import annotations

import argparse
import base64
import copy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Protocol, Sequence

import gcloud_custody
import gcp_proof_fleet as fleet_contract


TOOLS = Path(__file__).resolve().parent
TOOLCHAIN_PINS = TOOLS / "toolchain-pins.json"
MANIFEST_TOOL = TOOLS / "gcp_deployment_inputs.py"
CLIENT_BINDING_TOOL = TOOLS / "gcp_client_release_binding.py"
REMOTE_HELPER = TOOLS / "gcp_proof_remote_install.py"
REMOTE_HELPER_SHA256 = "10e726bf596deff646f1c5cd8b88c5e67bab60efcbf53e0feb66cc88e9808c26"
PROOF_KEY_PROVISION_ID = "winsvpn.gcp_proof.winn3_on_vm_key_provision.v1"
PROOF_KEY_PROVISION_FLAG = "--on-vm-generate"
OWNER_CLOUD_EVIDENCE_BLOCKED = (
    "BLOCKED: owner/cloud GCE instance identity is absent"
)
EXCHANGE_CONTRACT = "winsvpn-gcp-proof-authenticated-key-exchange-v1"
EXCHANGE_SOURCE_ROLE = "data-winn3"
EXCHANGE_TARGET_ROLE = "control"
PROOF_CLIENT_INNER_V4 = "10.10.0.2"
PROOF_CLIENT_PUB_PATH = "/etc/winn/proof-client/client.pub"
EXCHANGE_MAX_BYTES = 64 * 1024
EXCHANGE_ACTIONS = (
    "exchange-identity",
    "exchange-challenge",
    "exchange-control-offer",
    "exchange-data-accept",
    "exchange-data-emit",
    "exchange-control-import",
    "exchange-data-consume",
    "exchange-control-seal",
    "exchange-status",
)
# The helper arrives in /tmp as untrusted data. Never ask root's Python to
# execute that pathname directly: another process with the SSH user's uid can
# replace a /tmp entry after upload and before Python opens it. This fixed
# bootstrap is carried inside the authenticated SSH command, opens the helper
# with O_NOFOLLOW, binds every read to one inode, checks the reviewed digest,
# and executes only the bytes already held in memory. A concurrent replacement
# can therefore cause a refusal, but cannot substitute root-executed code.
REMOTE_HELPER_BOOTSTRAP = r"""import hashlib,os,stat,sys
p=sys.argv[1]
expected=sys.argv[2]
flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
before=os.lstat(p)
fd=os.open(p,flags)
try:
 opened=os.fstat(fd)
 chunks=[]
 while True:
  chunk=os.read(fd,1048576)
  if not chunk: break
  chunks.append(chunk)
 finished=os.fstat(fd)
finally:
 os.close(fd)
after=os.lstat(p)
identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink,stat.S_IFMT(value.st_mode))
if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or identity(before)!=identity(opened) or identity(opened)!=identity(finished) or identity(finished)!=identity(after):
 raise SystemExit("remote helper identity changed or is unsafe")
data=b"".join(chunks)
if hashlib.sha256(data).hexdigest()!=expected:
 raise SystemExit("remote helper digest mismatch")
sys.argv=[p,*sys.argv[3:]]
scope={"__name__":"__main__","__file__":p,"__package__":None,"__cached__":None}
exec(compile(data,p,"exec"),scope,scope)
"""
# Same helper-byte bind as REMOTE_HELPER_BOOTSTRAP, then optional in-memory stdin
# for peer documents or a kernel SSH pipe. pipe-consumer stdout is only the
# custody SSH-pipe receipt; helper secret fields never leave the VM pipe.
REMOTE_EXCHANGE_BOOTSTRAP = r"""import base64,hashlib,io,json,os,stat,sys
p=sys.argv[1]
expected=sys.argv[2]
stdin_mode=sys.argv[3]
stdout_mode=sys.argv[4]
flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
before=os.lstat(p)
fd=os.open(p,flags)
try:
 opened=os.fstat(fd)
 chunks=[]
 while True:
  chunk=os.read(fd,1048576)
  if not chunk: break
  chunks.append(chunk)
 finished=os.fstat(fd)
finally:
 os.close(fd)
after=os.lstat(p)
identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink,stat.S_IFMT(value.st_mode))
if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or identity(before)!=identity(opened) or identity(opened)!=identity(finished) or identity(finished)!=identity(after):
 raise SystemExit("remote helper identity changed or is unsafe")
data=b"".join(chunks)
if hashlib.sha256(data).hexdigest()!=expected:
 raise SystemExit("remote helper digest mismatch")
if stdin_mode=="none":
 stdin_data=b""
elif stdin_mode=="pipe":
 stdin_data=sys.stdin.buffer.read(65537)
 if len(stdin_data)>65536:
  raise SystemExit("authenticated key exchange v1 document is too large")
elif stdin_mode.startswith("b64:"):
 try:
  stdin_data=base64.b64decode(stdin_mode[4:].encode("ascii"),validate=True)
 except Exception:
  raise SystemExit("authenticated key exchange v1 stdin is invalid")
 if len(stdin_data)>65536:
  raise SystemExit("authenticated key exchange v1 document is too large")
else:
 raise SystemExit("exchange stdin mode is invalid")
sys.argv=[p,*sys.argv[5:]]
sys.stdin=io.TextIOWrapper(io.BytesIO(stdin_data),encoding="ascii")
scope={"__name__":"__main__","__file__":p,"__package__":None,"__cached__":None}
if stdout_mode=="helper":
 exec(compile(data,p,"exec"),scope,scope)
elif stdout_mode=="pipe-consumer":
 captured=io.BytesIO()
 real_stdout=sys.stdout
 sys.stdout=io.TextIOWrapper(captured,encoding="ascii",write_through=True)
 code=0
 try:
  exec(compile(data,p,"exec"),scope,scope)
 except SystemExit as exc:
  code=exc.code if type(exc.code) is int else 1
 raw=captured.getvalue()
 if code!=0:
  raise SystemExit(code)
 try:
  parsed=json.loads(raw.decode("ascii"))
 except Exception:
  raise SystemExit("pipe consumer response is invalid")
 if not isinstance(parsed,dict) or parsed.get("kind")!="winsvpn.gcp_proof.authenticated_key_exchange_response.v1" or parsed.get("secret") is not None:
  raise SystemExit("pipe consumer emitted secret material or an invalid helper response")
 digest=hashlib.sha256(raw).hexdigest()
 payload={"contract":"winsvpn-gcloud-ssh-pipe-response-v1","payload_sha256":digest,"schema_version":1,"status":"ok"}
 real_stdout.write(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")
else:
 raise SystemExit("exchange stdout mode is invalid")
"""
REMOTE_EXCHANGE_BOOTSTRAP = (
    "import base64;exec(compile(base64.b64decode('"
    + base64.b64encode(REMOTE_EXCHANGE_BOOTSTRAP.encode("ascii")).decode("ascii")
    + "'),'<winsvpn-exchange-bootstrap>','exec'))"
)
REMOTE_RUNTIME_PROBE_BOOTSTRAP = r"""import json,os,re,stat,sys
role=sys.argv[1]
if role not in ("control","data-winn3","data-cover"):
 raise SystemExit("runtime probe role is invalid")
flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
def read_text(path):
 before=os.lstat(path)
 if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:
  raise SystemExit("runtime probe target is unsafe")
 fd=os.open(path,flags)
 try:
  opened=os.fstat(fd)
  data=b""
  while True:
   chunk=os.read(fd,4096)
   if not chunk: break
   data+=chunk
  finished=os.fstat(fd)
 finally:
  os.close(fd)
 after=os.lstat(path)
 ident=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink,stat.S_IFMT(value.st_mode))
 if ident(before)!=ident(opened) or ident(opened)!=ident(finished) or ident(finished)!=ident(after):
  raise SystemExit("runtime probe target changed")
 return data
marker=None
try:
 marker=json.loads(read_text("/var/lib/winsvpn-proof/deployment-identity.json").decode("ascii"))
except FileNotFoundError:
 marker=None
instance_id=None
boot_id=None
status="ok"
if role in ("control","data-winn3"):
 text=""
 try:
  text=read_text("/var/lib/winsvpn-proof/instance-id").decode("ascii").strip()
 except FileNotFoundError:
  text=""
 if not re.fullmatch(r"[1-9][0-9]{0,31}",text or ""):
  try:
   serial=read_text("/sys/class/dmi/id/product_serial").decode("ascii").strip()
  except FileNotFoundError:
   serial=""
  matched=re.fullmatch(r"GoogleCloud-([1-9][0-9]{0,31})",serial)
  text=matched.group(1) if matched else ""
 boot=""
 try:
  boot=read_text("/proc/sys/kernel/random/boot_id").decode("ascii").strip()
 except FileNotFoundError:
  boot=""
 if not re.fullmatch(r"[1-9][0-9]{0,31}",text or "") or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",boot or ""):
  status="blocked"
 else:
  instance_id=text
  boot_id=boot
payload={"boot_id":boot_id,"instance_id":instance_id,"kind":"winsvpn.gcp_proof.runtime_probe.v1","marker":marker,"role":role,"schema_version":1,"status":status}
sys.stdout.write(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")
if status!="ok":
 raise SystemExit(2)
"""
REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP = r"""import json,os,re,stat,sys
path="/etc/winn/proof-client/client.pub"
flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
before=os.lstat(path)
fd=os.open(path,flags)
try:
 opened=os.fstat(fd)
 data=b""
 while True:
  chunk=os.read(fd,4096)
  if not chunk: break
  data+=chunk
 finished=os.fstat(fd)
finally:
 os.close(fd)
after=os.lstat(path)
ident=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink,stat.S_IFMT(value.st_mode))
if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or ident(before)!=ident(opened) or ident(opened)!=ident(finished) or ident(finished)!=ident(after):
 raise SystemExit("client.pub identity changed or is unsafe")
text=data.strip()
if not re.fullmatch(rb"[0-9a-f]{64}",text):
 raise SystemExit("client.pub is not exact hex")
payload={"action":"exchange-data-consume","contract":"winsvpn-gcp-proof-authenticated-key-exchange-v1","kind":"winsvpn.gcp_proof.authenticated_key_exchange_response.v1","public":{"client.pub":text.decode("ascii")},"receipt":None,"schema_version":1,"secret":None}
sys.stdout.write(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")
"""
REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP = (
    "import base64;exec(compile(base64.b64decode('"
    + base64.b64encode(REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP.encode("ascii")).decode("ascii")
    + "'),'<winsvpn-exchange-public-bootstrap>','exec'))"
)
KIND_PLAN = "winsvpn.gcp_proof_fleet.plan.v4"
KIND_APPLY = "winsvpn.gcp_proof_fleet.apply.v4"
KIND_EXECUTION = "winsvpn.gcp_proof.deployment_execution.v3"
KIND_RESPONSE = "winsvpn.gcp_proof.remote_install_response.v1"
KIND_RECORD = "winsvpn.gcp_proof.deployment_step_record.v1"
KIND_MARKER = "winsvpn.gcp_proof.deployment_identity.v1"
KIND_ROLLBACK = "winsvpn.gcp_proof.remote_rollback_response.v1"
KIND_DEPLOYMENT_OBSERVATION = "winsvpn.gcp_proof.deployment_observation.v1"
KIND_EXCHANGE_RESPONSE = "winsvpn.gcp_proof.authenticated_key_exchange_response.v1"
KIND_RUNTIME_PROBE = "winsvpn.gcp_proof.runtime_probe.v1"
SCHEMA_VERSION = 4
EXECUTION_SCHEMA_VERSION = 3
EXCHANGE_RESPONSE_KEYS = {
    "action", "contract", "kind", "public", "receipt", "schema_version", "secret",
}
RUNTIME_PROBE_KEYS = {
    "boot_id", "instance_id", "kind", "marker", "role", "schema_version", "status",
}
SSH_PIPE_RESPONSE_CONTRACT = "winsvpn-gcloud-ssh-pipe-response-v1"
# One exact receipt schema. Fleet consumes these fields as written; candidate_id,
# cleanup, preflight, and record_chain_sha256 are never synthesized later.
EXECUTION_KEYS = {
    "apply_sha256",
    "bundle_sha256",
    "candidate_id",
    "cleanup",
    "client_release_binding",
    "deployment_inputs",
    "deployment_manifest_sha256",
    "ended_utc",
    "failure",
    "fleet_id",
    "kind",
    "markers",
    "plan_sha256",
    "preflight",
    "record_chain_sha256",
    "records",
    "remote_helper_sha256",
    "schema_version",
    "started_utc",
    "status",
}
CLEANUP_KEYS = {
    "acceptance_receipt_required",
    "authorized",
    "remote",
    "resources",
    "status",
}
CLEANUP_RESOURCES_KEYS = {
    "reason",
    "results",
    "status",
    "targets",
}
PREFLIGHT_KEYS = {
    "firewalls",
    "instances",
    "network",
    "subnets",
}
RESOURCE_TYPES = {
    "firewall": "compute#firewall",
    "network": "compute#network",
    "subnet": "compute#subnetwork",
}
CLIENT_BINDING_REFERENCE_CONTRACT = "winsvpn-gcp-client-release-binding-reference-v1"
CLIENT_BINDING_REFERENCE_KEYS = {
    "binding", "binding_sha256", "contract", "repo_root", "schema_version",
    "verifier_closure",
}
CLIENT_BINDING_KEYS = {
    "artifact", "artifact_input_fingerprint_sha256", "build_identity",
    "build_receipt", "contract", "platform", "release",
    "release_input_index", "schema_version", "shared_revision", "proof_build",
}
CLIENT_PROOF_BUILD_KEYS = {
    "build_contract", "build_identity", "builder", "defines", "source",
    "target", "toolchain", "toolchain_pin_manifest",
}
CLIENT_BINDING_FILE_KEYS = {"bytes", "path", "sha256"}
CLIENT_BINDING_CLOSURE_KEYS = {
    "proof_client_builder", "client_release_binding", "release_dependency_freeze"
}
ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GCE_NAME_RE = re.compile(r"[a-z]([-a-z0-9]{0,61}[a-z0-9])?\Z")
GCE_ZONE_RE = re.compile(r"[a-z]+-[a-z]+[0-9]+-[a-z]\Z")
MACHINE_TYPE_RE = re.compile(r"[a-z][a-z0-9]*-[a-z0-9-]+\Z")
PROJECT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
FLEET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
CREATED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
GCE_ID_RE = re.compile(r"[1-9][0-9]{0,31}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
TOKEN_RE = re.compile(r"[0-9a-f]{24}\Z")
SERVICE_RE = re.compile(r"[a-z][a-z0-9_.-]*\.service\Z")
UNIT_RE = re.compile(r"[a-z][a-z0-9_.-]*\.(?:service|socket)\Z")
FINGERPRINT_RE = re.compile(r"[A-Za-z0-9+/_-]{8,128}={0,3}\Z")
SELF_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/zones/"
    r"([a-z]+-[a-z]+[0-9]+-[a-z])/instances/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)\Z"
)
ZONE_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/zones/"
    r"([a-z]+-[a-z]+[0-9]+-[a-z])\Z"
)
MACHINE_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/zones/"
    r"([a-z]+-[a-z]+[0-9]+-[a-z])/machineTypes/"
    r"([a-z][a-z0-9]*-[a-z0-9-]+)\Z"
)
FIREWALL_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/global/firewalls/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)\Z"
)
NETWORK_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/global/networks/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)\Z"
)
SUBNET_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/regions/"
    r"([a-z]+-[a-z]+[0-9]+)/subnetworks/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)\Z"
)
REGION_LINK_RE = re.compile(
    r"https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/regions/"
    r"([a-z]+-[a-z]+[0-9]+)\Z"
)
SECRET_RE = re.compile(
    rb"(?i)(-----BEGIN [^-\r\n]{0,40}PRIVATE KEY-----|"
    rb"\bAIza[0-9A-Za-z_-]{20,}|\bya29\.[0-9A-Za-z._-]+|"
    rb"(?:access[_-]?token|admin[_-]?token|api[_-]?key|client[_-]?secret|"
    rb"private[_-]?key|password|authorization)\s*[:=]\s*[^\s,;]+)"
)
MAX_CAPTURE_BYTES = 1024 * 1024
RESERVED_INSTANCE_NAMES = {
    "control-sim", "data-sim", "core-sim", "data-sim-winn3gw",
    "xprize-hub", "xprize-route-a", "xprize-route-b",
}
RESERVED_NAME_MARKERS = {
    "control-sim", "data-sim", "core-sim", "data-sim-winn3gw",
    "xprize", "xprize-hub", "xprize-route-a", "xprize-route-b",
}
RESERVED_PROJECT_MARKERS = {"prod", "production", "xprize", "staging", "live"}
EXPECTED_STEPS: tuple[tuple[str, str, str], ...] = (
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--preflight"),
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--deploy"),
    ("data-winn3", "server/wins_winn3_gateway_install.sh", "--install"),
    ("data-winn3", PROOF_KEY_PROVISION_ID, PROOF_KEY_PROVISION_FLAG),
    ("data-winn3", "server/wins_winn3_gateway_install.sh", "--preflight"),
    ("data-winn3", "server/wins_winn3_gateway_install.sh", "--start"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--preflight"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),
)
LAST_ROLE_STEP = {"control": 1, "data-winn3": 5, "data-cover": 7}
ROLES = ("control", "data-winn3", "data-cover")
REMOTE_MARKER = "/var/lib/winsvpn-proof/deployment-identity.json"
REMOTE_STATE = "/var/lib/winsvpn-proof"
FRESHNESS_WINDOW = timedelta(hours=6)
MAX_CLOCK_SKEW = timedelta(minutes=5)
DESCRIBE_FORMAT = (
    "--format=json(id,name,status,zone,machineType,creationTimestamp,"
    "labels,tags.items,deletionProtection,metadata.items,selfLink,"
    "serviceAccounts,shieldedInstanceConfig,canIpForward)"
)
FIREWALL_DESCRIBE_FORMAT = (
    "--format=json(id,name,kind,creationTimestamp,selfLink,network,"
    "labels,labelFingerprint,fingerprint)"
)
SUBNET_DESCRIBE_FORMAT = (
    "--format=json(id,name,kind,creationTimestamp,selfLink,region,network,"
    "ipCidrRange,labels,labelFingerprint,fingerprint)"
)
NETWORK_DESCRIBE_FORMAT = (
    "--format=json(id,name,kind,creationTimestamp,selfLink,"
    "autoCreateSubnetworks,routingConfig.routingMode,labels,"
    "labelFingerprint,fingerprint)"
)
FORBIDDEN_SELECTION_FLAGS = ("--filter", "--regex", "--all")
ROLLBACK_SERVICES = {
    "control": (
        "winsvpn-gcp-proof-attempt-broker.socket",
        "winsvpn-gcp-proof-attempt-broker.service",
        "winsvpn-proof-winn3-probe.service",
        "winsvpn-proof-awg-client.service",
        "winsvpn-proof-xray-client.service",
        "winsvpn-proof-xray-probe.service",
        "wins-hub.service",
        "winn3-gateway.service",
    ),
    "data-winn3": ("winn3-gateway.service", "xray.service", "docker.service"),
    "data-cover": ("winn3-gateway.service", "xray.service", "docker.service"),
}
ROLLBACK_RESIDUAL_CLASSES = (
    "binaries", "config", "firewall_nat", "timers", "units", "users",
)
ROLLBACK_RESIDUALS = {
    "control": {
        "binaries": (
            "/usr/local/bin/amneziawg-go",
            "/usr/local/bin/awg",
            "/usr/local/bin/winn3-gateway",
            "/usr/local/bin/winn3-probe",
            "/usr/local/bin/wins-admin",
            "/usr/local/bin/xray",
            "/usr/local/libexec/winsvpn-gcp-proof-attempt-broker",
            "/usr/local/libexec/winsvpn-gcp-proof-remote",
        ),
        "config": (
            "/etc/winsvpn", "/etc/winsvpn/role", "/etc/winn",
            "/etc/winn/proof-client", "/etc/winn/proof-client/awg0.conf",
            "/etc/winn/proof-client/winn3-probe.env",
            "/etc/winn/proof-client/xray-client.json",
            "/etc/winn/proof-client/xray-probe.env",
            "/var/lib/winsvpn-proof",
            "/var/lib/winsvpn-proof/attempt-broker.json",
            "/var/lib/winsvpn-proof/fleet-binding.json",
            "/var/lib/winsvpn",
        ),
        "firewall_nat": (
            "filter:WINVPN-INPUT", "filter:WINN3GW-FORWARD", "filter:WINN3GW-INPUT",
            "nat:WINN3GW-NAT-POSTROUTING",
        ),
        "timers": (
            "wins-hub-backup.timer", "wins-hub-backup-prune.timer",
            "wins-weekly-maintenance.timer", "wins-gateway-canary.timer",
        ),
        "units": (
            "wins-hub.service",
            "winn3-gateway.service",
            "winsvpn-gcp-proof-attempt-broker.service",
            "winsvpn-gcp-proof-attempt-broker.socket",
            "winsvpn-proof-awg-client.service",
            "winsvpn-proof-winn3-probe.service",
            "winsvpn-proof-xray-client.service",
            "winsvpn-proof-xray-probe.service",
        ),
        "users": ("winn3-gateway", "xray", "cloudflared"),
    },
    "data-winn3": {
        "binaries": ("/usr/local/bin/winn3-gateway", "/usr/local/bin/xray"),
        "config": (
            "/etc/winsvpn", "/etc/winn", "/var/lib/winsvpn-proof", "/var/lib/winsvpn",
        ),
        "firewall_nat": (
            "filter:WINVPN-INPUT", "filter:WINN3GW-FORWARD", "filter:WINN3GW-INPUT",
            "nat:WINN3GW-NAT-POSTROUTING",
        ),
        "timers": (
            "wins-node-register.timer", "wins-node-backup.timer",
            "wins-vpn-firewall-reapply.timer", "wins-weekly-maintenance.timer",
        ),
        "units": (
            "winn3-gateway.service", "xray.service", "docker.service",
            "wins-vpn-firewall.service",
        ),
        "users": ("winn3-gateway", "xray"),
    },
    "data-cover": {
        "binaries": ("/usr/local/bin/winn3-gateway", "/usr/local/bin/xray"),
        "config": (
            "/etc/winsvpn", "/etc/winn", "/var/lib/winsvpn-proof", "/var/lib/winsvpn",
        ),
        "firewall_nat": (
            "filter:WINVPN-INPUT", "filter:WINN3GW-FORWARD", "filter:WINN3GW-INPUT",
            "nat:WINN3GW-NAT-POSTROUTING",
        ),
        "timers": (
            "wins-node-register.timer", "wins-node-backup.timer",
            "wins-vpn-firewall-reapply.timer", "wins-weekly-maintenance.timer",
        ),
        "units": (
            "winn3-gateway.service", "xray.service", "docker.service",
            "wins-vpn-firewall.service",
        ),
        "users": ("winn3-gateway", "xray"),
    },
}
ROLLBACK_STAGED_FILE_RE = re.compile(
    r"/tmp/winsvpn-proof-[0-9a-f]{24}"
    r"(?:\.tar|-remote\.py|-DEPLOYMENT_INPUTS\.json(?:\.sha256)?)\Z"
)
ROLLBACK_RESPONSE_REQUIRED_KEYS = {
    "errors", "fleet_id", "instance", "kind", "ok", "removed_files", "role",
    "schema_version", "services_stopped", "state_removed", "inspected", "residuals",
}
ROLLBACK_RESPONSE_OPTIONAL_KEYS: set[str] = set()
# Wrapper-only. Applied to Compute 404 envelope text after the quoted
# resource identifier is removed; never to the validated name/path itself.
AUTH_OR_SERVICE_ACCOUNT_RE = re.compile(
    rb"(?i)(?:service[ _-]?account|serviceAccounts/|iamcredentials|"
    rb"impersonat|\boauth\b|access[_ -]?token|application-default|"
    rb"permission[_ -]?denied|insufficient permission|"
    rb"unauthorized|unauthenticated|\bforbidden\b|"
    rb"invalid[_-]?grant|invalid authentication credentials|"
    rb"\b401\b|\b403\b|"
    rb"gcloud auth login|\bget-iam-policy\b|\biam\b|"
    rb"api(?:\s+\[[^\]]+\])?(?:\s+\S+)?(?:\s+has not been used|"
    rb"\s+has been disabled|\s+is disabled|\s+not enabled|\s+disabled)|"
    rb"apis? disabled|"
    rb"\bgrpc\b|grpc[_-]?status|"
    rb"statuscode\.permission_denied|"
    rb"\bcode\s*[:=]\s*7\b|"
    rb"reauth(?:entication)?|"
    rb"auth[_ -]?tokens?|"
    rb"\bcredentials\b)"
)
_ALLOWED_COMPUTE_DESCRIBE_TAIL = (
    rb"compute\.(?:instances|firewall-rules|networks(?:\.subnets)?)\.describe"
)
NON_COMPUTE_PRODUCT_ENVELOPE_RE = re.compile(
    rb"(?i)(?:\(gcloud\.(?!" + _ALLOWED_COMPUTE_DESCRIBE_TAIL + rb")|"
    rb"\bgcloud\.(?:functions|run|sql|storage|container|pubsub)\b|"
    rb"\bgcloud\.compute\.(?:disks|addresses)\b)"
)
CLEANUP_PLAN_MUTATIONS = {
    "delete-firewall", "delete-instance", "delete-network", "delete-subnet",
    "disable-deletion-protection",
}
# Exact-path rollback of this fleet's staged uploads, extracted candidate tree,
# and role services, then bounded residual inspection. Paths, unit names, users,
# binaries, timers, and host firewall/NAT chain names are fixed from the
# authenticated candidate token and role; the script refuses any other target.
REMOTE_ROLLBACK_BOOTSTRAP = r"""import json,os,shlex,shutil,stat,subprocess,sys
token,role,instance,fleet=sys.argv[1:5]
files=list(sys.argv[5:9])
state=sys.argv[9]
expected=[
 f"/tmp/winsvpn-proof-{token}.tar",
 f"/tmp/winsvpn-proof-{token}-remote.py",
 f"/tmp/winsvpn-proof-{token}-DEPLOYMENT_INPUTS.json",
 f"/tmp/winsvpn-proof-{token}-DEPLOYMENT_INPUTS.json.sha256",
]
units={"control":["winsvpn-gcp-proof-attempt-broker.socket","winsvpn-gcp-proof-attempt-broker.service","winsvpn-proof-winn3-probe.service","winsvpn-proof-awg-client.service","winsvpn-proof-xray-client.service","winsvpn-proof-xray-probe.service","wins-hub.service","winn3-gateway.service"],"data-winn3":["winn3-gateway.service","xray.service","docker.service"],"data-cover":["winn3-gateway.service","xray.service","docker.service"]}
residuals_spec={"control":{"binaries":["/usr/local/bin/amneziawg-go","/usr/local/bin/awg","/usr/local/bin/winn3-gateway","/usr/local/bin/winn3-probe","/usr/local/bin/wins-admin","/usr/local/bin/xray","/usr/local/libexec/winsvpn-gcp-proof-attempt-broker","/usr/local/libexec/winsvpn-gcp-proof-remote"],"config":["/etc/winsvpn","/etc/winsvpn/role","/etc/winn","/etc/winn/proof-client","/etc/winn/proof-client/awg0.conf","/etc/winn/proof-client/winn3-probe.env","/etc/winn/proof-client/xray-client.json","/etc/winn/proof-client/xray-probe.env","/var/lib/winsvpn-proof","/var/lib/winsvpn-proof/attempt-broker.json","/var/lib/winsvpn-proof/fleet-binding.json","/var/lib/winsvpn"],"firewall_nat":["filter:WINVPN-INPUT","filter:WINN3GW-FORWARD","filter:WINN3GW-INPUT","nat:WINN3GW-NAT-POSTROUTING"],"timers":["wins-hub-backup.timer","wins-hub-backup-prune.timer","wins-weekly-maintenance.timer","wins-gateway-canary.timer"],"units":["wins-hub.service","winn3-gateway.service","winsvpn-gcp-proof-attempt-broker.service","winsvpn-gcp-proof-attempt-broker.socket","winsvpn-proof-awg-client.service","winsvpn-proof-winn3-probe.service","winsvpn-proof-xray-client.service","winsvpn-proof-xray-probe.service"],"users":["winn3-gateway","xray","cloudflared"]},"data-winn3":{"binaries":["/usr/local/bin/winn3-gateway","/usr/local/bin/xray"],"config":["/etc/winsvpn","/etc/winn","/var/lib/winsvpn-proof","/var/lib/winsvpn"],"firewall_nat":["filter:WINVPN-INPUT","filter:WINN3GW-FORWARD","filter:WINN3GW-INPUT","nat:WINN3GW-NAT-POSTROUTING"],"timers":["wins-node-register.timer","wins-node-backup.timer","wins-vpn-firewall-reapply.timer","wins-weekly-maintenance.timer"],"units":["winn3-gateway.service","xray.service","docker.service","wins-vpn-firewall.service"],"users":["winn3-gateway","xray"]},"data-cover":{"binaries":["/usr/local/bin/winn3-gateway","/usr/local/bin/xray"],"config":["/etc/winsvpn","/etc/winn","/var/lib/winsvpn-proof","/var/lib/winsvpn"],"firewall_nat":["filter:WINVPN-INPUT","filter:WINN3GW-FORWARD","filter:WINN3GW-INPUT","nat:WINN3GW-NAT-POSTROUTING"],"timers":["wins-node-register.timer","wins-node-backup.timer","wins-vpn-firewall-reapply.timer","wins-weekly-maintenance.timer"],"units":["winn3-gateway.service","xray.service","docker.service","wins-vpn-firewall.service"],"users":["winn3-gateway","xray"]}}
if files!=expected or state!="/var/lib/winsvpn-proof" or role not in units or role not in residuals_spec:
 raise SystemExit("rollback target identity is invalid")
removed=[]
errors=[]
for path in files:
 try:
  info=os.lstat(path)
 except FileNotFoundError:
  continue
 if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
  errors.append("unsafe-file")
  continue
 os.unlink(path)
 removed.append(path)
stopped=[]
for unit in units[role]:
 try:
  action=["systemctl","disable","--now",unit]
  result=subprocess.run(action,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,check=False)
 except OSError:
  errors.append(unit)
  continue
 if result.returncode not in (0,5):
  errors.append(unit)
 else:
  stopped.append(unit)
state_removed=False
try:
 info=os.lstat(state)
except FileNotFoundError:
 pass
else:
 if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
  errors.append("unsafe-state")
 else:
  shutil.rmtree(state)
  state_removed=True
spec=residuals_spec[role]
for timer in spec["timers"]:
 try:
  result=subprocess.run(["systemctl","disable","--now",timer],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,check=False)
 except OSError:
  errors.append(timer)
  continue
 if result.returncode not in (0,5): errors.append(timer)
for path in list(spec["binaries"])+["/etc/systemd/system/"+unit for unit in list(spec["units"])+list(spec["timers"])]:
 try:
  info=os.lstat(path)
 except FileNotFoundError:
  continue
 if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
  errors.append("unsafe-installed-file")
  continue
 os.unlink(path)
 removed.append(path)
def remove_config(path):
 try:
  info=os.lstat(path)
 except FileNotFoundError:
  return
 if stat.S_ISLNK(info.st_mode):
  errors.append("unsafe-config")
 elif stat.S_ISDIR(info.st_mode):
  shutil.rmtree(path)
  removed.append(path)
 elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
  os.unlink(path)
  removed.append(path)
 else:
  errors.append("unsafe-config")
for path in sorted(spec["config"],key=lambda value:(value.count("/"),len(value)),reverse=True):
 remove_config(path)
def run_capture(argv):
 try:
  return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,shell=False,check=False,text=True)
 except OSError:
  return None
for item in spec["firewall_nat"]:
 table,chain=item.split(":")
 listed=run_capture(["iptables","-w","5","-t",table,"-S"])
 if listed is None:
  errors.append("firewall-inspection")
  continue
 if listed.returncode not in (0,1):
  errors.append("firewall-inspection")
  continue
 for line in listed.stdout.splitlines():
  try: parts=shlex.split(line)
  except ValueError:
   errors.append("firewall-inspection")
   continue
  if len(parts)>=4 and parts[0]=="-A" and "-j" in parts:
   jump=parts.index("-j")
   if jump+1<len(parts) and parts[jump+1]==chain:
    deleted=run_capture(["iptables","-w","5","-t",table,"-D"]+parts[1:])
    if deleted is None or deleted.returncode!=0: errors.append("firewall-rule-delete")
 flush=run_capture(["iptables","-w","5","-t",table,"-F",chain])
 delete=run_capture(["iptables","-w","5","-t",table,"-X",chain])
 if (flush is not None and flush.returncode==0) and (delete is None or delete.returncode!=0): errors.append("firewall-chain-delete")
for user in spec["users"]:
 present=run_capture(["getent","passwd",user])
 if present is None:
  errors.append("user-inspection")
 elif present.returncode==0:
  deleted=run_capture(["userdel",user])
  if deleted is None or deleted.returncode!=0: errors.append("user-delete")
try:
 reload_result=subprocess.run(["systemctl","daemon-reload"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,check=False)
 if reload_result.returncode!=0: errors.append("daemon-reload")
except OSError:
 errors.append("daemon-reload")
def exists(path):
 try:
  os.lstat(path)
 except FileNotFoundError:
  return False
 return True
def run(argv):
 try:
  return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,check=False).returncode
 except OSError:
  return -1
residuals={"binaries":[],"config":[],"firewall_nat":[],"timers":[],"units":[],"users":[]}
for path in spec["binaries"]:
 if exists(path): residuals["binaries"].append(path)
for path in spec["config"]:
 if exists(path): residuals["config"].append(path)
for unit in spec["units"]:
 if exists("/etc/systemd/system/"+unit) or run(["systemctl","is-active","--quiet",unit])==0 or run(["systemctl","is-enabled","--quiet",unit])==0:
  residuals["units"].append(unit)
for timer in spec["timers"]:
 if exists("/etc/systemd/system/"+timer) or run(["systemctl","is-active","--quiet",timer])==0:
  residuals["timers"].append(timer)
for user in spec["users"]:
 if run(["getent","passwd",user])==0:
  residuals["users"].append(user)
for item in spec["firewall_nat"]:
 table,chain=item.split(":")
 if run(["iptables","-w","5","-t",table,"-n","-L",chain])==0:
  residuals["firewall_nat"].append(item)
if any(residuals[key] for key in residuals):
 errors.append("residuals-present")
inspected=["binaries","config","firewall_nat","timers","units","users"]
payload={"errors":errors,"fleet_id":fleet,"inspected":inspected,"instance":instance,"kind":"winsvpn.gcp_proof.remote_rollback_response.v1","ok":not errors,"removed_files":removed,"residuals":residuals,"role":role,"schema_version":1,"services_stopped":stopped,"state_removed":state_removed}
sys.stdout.write(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")
raise SystemExit(0 if not errors else 1)
"""

# This observer is executed from fixed inline bytes after all authenticated
# installer steps and marker finalizations. Its expected file set is derived
# only from the authenticated deployment manifest. A passed deployment cannot
# therefore rely on the installer response alone for control-role broker state.
REMOTE_DEPLOYMENT_OBSERVATION_BOOTSTRAP = r"""import hashlib,json,os,stat,subprocess,sys
def pairs(values):
 result={}
 for key,value in values:
  if key in result: raise SystemExit("duplicate observation spec key")
  result[key]=value
 return result
spec=json.loads(sys.argv[1],object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ValueError(value)))
if not isinstance(spec,dict) or set(spec)!={"client_units","files","role","service","socket"} or spec["role"]!="control":
 raise SystemExit("deployment observation spec is invalid")
def stable_file(item):
 if not isinstance(item,dict) or set(item)!={"bytes","mode","path","sha256"}: raise SystemExit("observation file spec is invalid")
 path=item["path"]
 if not isinstance(path,str) or not path.startswith("/") or not isinstance(item["bytes"],int) or item["bytes"]<0 or not isinstance(item["mode"],int): raise SystemExit("observation file spec value is invalid")
 before=os.lstat(path)
 if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0 or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=item["mode"]: raise SystemExit("observed file custody is invalid")
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0))
 try:
  opened=os.fstat(fd); chunks=[]
  while True:
   chunk=os.read(fd,1048576)
   if not chunk: break
   chunks.append(chunk)
  finished=os.fstat(fd)
 finally:
  os.close(fd)
 after=os.lstat(path)
 identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink,stat.S_IFMT(value.st_mode))
 data=b"".join(chunks)
 if identity(before)!=identity(opened) or identity(opened)!=identity(finished) or identity(finished)!=identity(after) or len(data)!=item["bytes"] or hashlib.sha256(data).hexdigest()!=item["sha256"]: raise SystemExit("observed file identity changed or digest mismatched")
 return path
files=spec["files"]
if not isinstance(files,list) or not files: raise SystemExit("deployment observation files are invalid")
verified=[stable_file(item) for item in files]
def run(argv):
 try:
  return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,shell=False,check=False,timeout=30,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"})
 except (OSError,subprocess.TimeoutExpired): raise SystemExit("systemd observation failed")
def unit(name,active_required,enabled_required):
 if not isinstance(name,str) or not name.startswith("winsvpn-") or not name.endswith((".service",".socket")): raise SystemExit("observed unit name is invalid")
 loaded=run(["/usr/bin/systemctl","show","--property=LoadState","--value",name])
 active=run(["/usr/bin/systemctl","is-active","--quiet",name])
 failed=run(["/usr/bin/systemctl","is-failed","--quiet",name])
 enabled=run(["/usr/bin/systemctl","is-enabled","--quiet",name])
 if loaded.returncode!=0 or loaded.stdout.strip()!=b"loaded" or failed.returncode==0 or active.returncode not in (0,3) or (active_required and active.returncode!=0) or (enabled_required and enabled.returncode!=0): raise SystemExit("observed systemd unit state is invalid")
 return {"active":active.returncode==0,"enabled":enabled.returncode==0,"failed":False,"installed":True,"name":name}
socket=unit(spec["socket"],True,True)
service=unit(spec["service"],False,False)
clients=spec["client_units"]
if not isinstance(clients,list) or len(clients)!=4 or len(set(clients))!=4: raise SystemExit("observed proof client unit set is invalid")
for name in clients: unit(name,False,False)
payload={"client_units_verified":clients,"files_verified":verified,"kind":"winsvpn.gcp_proof.deployment_observation.v1","role":"control","schema_version":1,"service":service,"socket":socket}
sys.stdout.write(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")
"""


class DeploymentRefused(RuntimeError):
    """The controlled deployment could not authenticate its full input chain."""


class DeploymentBlocked(DeploymentRefused):
    """Owner or cloud GCE identity proof is absent; the receipt is BLOCKED."""


@dataclass(frozen=True)
class RunResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> RunResult: ...


class SubprocessRunner:
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> RunResult:
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise DeploymentRefused("gcloud runner requires a nonempty argv vector")
        environment = os.environ.copy()
        environment["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=timeout_seconds,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise DeploymentRefused("gcloud command timed out") from exc
        except OSError as exc:
            raise DeploymentRefused("gcloud command could not be executed") from exc
        return RunResult(bytes(completed.stdout), bytes(completed.stderr), int(completed.returncode))


def verify_gcloud_version(runner: Runner, gcloud_bin: str) -> str:
    try:
        expected = gcloud_custody.parse_google_cloud_cli_pin_document(
            TOOLCHAIN_PINS.read_bytes()
        )["version"]
    except (OSError, KeyError, TypeError, gcloud_custody.GcloudCustodyError) as exc:
        raise DeploymentRefused("Google Cloud CLI toolchain pin is invalid") from exc
    result = runner.run([gcloud_bin, "version", "--format=json"], timeout_seconds=30)
    if result.exit_code != 0 or result.stderr.strip() or len(result.stdout) > 65536:
        raise DeploymentRefused("Google Cloud CLI version probe failed")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentRefused("Google Cloud CLI version output is invalid") from exc
    observed = payload.get("Google Cloud SDK") if isinstance(payload, dict) else None
    if not isinstance(expected, str) or observed != expected:
        raise DeploymentRefused(
            f"Google Cloud CLI version mismatch: expected {expected!r}, observed {observed!r}"
        )
    return expected


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentRefused(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentRefused(f"{label} is not strict ASCII JSON") from exc


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        stat.S_IFMT(item.st_mode),
        stat.S_IMODE(item.st_mode),
    )


def _read_stable(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    fd = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise DeploymentRefused(f"{label} is not a regular single-link file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
        after = path.lstat()
    except DeploymentRefused:
        raise
    except OSError as exc:
        raise DeploymentRefused(f"{label} is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not (_identity(before) == _identity(opened) == _identity(finished) == _identity(after)):
        raise DeploymentRefused(f"{label} changed while being read")
    return b"".join(chunks), opened


def _absolute_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise DeploymentRefused(f"{label} must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise DeploymentRefused(f"{label} does not exist") from exc
    if resolved != candidate or candidate.is_symlink() or not candidate.is_file():
        raise DeploymentRefused(f"{label} must be a canonical non-symlink file")
    return candidate


def _repo_root(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise DeploymentRefused("repo root must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
        info = candidate.lstat()
    except OSError as exc:
        raise DeploymentRefused("repo root does not exist") from exc
    if resolved != candidate or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise DeploymentRefused("repo root must be a canonical non-symlink directory")
    return candidate


def _load_immutable(path: Path, label: str) -> tuple[dict[str, Any], str, int]:
    candidate = _absolute_file(path, label)
    sidecar = _absolute_file(candidate.with_name(candidate.name + ".sha256"), f"{label} sidecar")
    data, info = _read_stable(candidate, label)
    anchor, anchor_info = _read_stable(sidecar, f"{label} sidecar")
    if not data:
        raise DeploymentRefused(f"{label} is empty")
    if stat.S_IMODE(info.st_mode) & 0o222 or stat.S_IMODE(anchor_info.st_mode) & 0o222:
        raise DeploymentRefused(f"{label} and sidecar must be immutable")
    if stat.S_IMODE(info.st_mode) & 0o077 or stat.S_IMODE(anchor_info.st_mode) & 0o077:
        raise DeploymentRefused(f"{label} and sidecar must be private")
    digest = sha256_bytes(data)
    if anchor != f"{digest}  {candidate.name}\n".encode("ascii"):
        raise DeploymentRefused(f"{label} sidecar does not match exact bytes")
    value = strict_json(data, label)
    if not isinstance(value, dict) or data != canonical_bytes(value):
        raise DeploymentRefused(f"{label} is not canonical ASCII JSON")
    return value, digest, len(data)


def _load_manifest_module() -> Any:
    spec = importlib.util.spec_from_file_location("winsvpn_gcp_deployment_inputs", MANIFEST_TOOL)
    if spec is None or spec.loader is None:
        raise DeploymentRefused("deployment manifest verifier could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_client_binding_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "winsvpn_gcp_client_release_binding", CLIENT_BINDING_TOOL
    )
    if spec is None or spec.loader is None:
        raise DeploymentRefused("client release binding verifier could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _binding_file_ref(path: Path, label: str) -> dict[str, Any]:
    candidate = _absolute_file(path, label)
    data, _ = _read_stable(candidate, label)
    if not data:
        raise DeploymentRefused(f"{label} is empty")
    return {"bytes": len(data), "path": str(candidate), "sha256": sha256_bytes(data)}


def _client_verifier_closure(module: Any) -> dict[str, Any]:
    return {
        "proof_client_builder": _binding_file_ref(
            Path(module.proof_builder.__file__).resolve(), "proof client builder"
        ),
        "client_release_binding": _binding_file_ref(
            Path(module.__file__).resolve(), "client release binding verifier"
        ),
        "release_dependency_freeze": _binding_file_ref(
            Path(module.freeze.__file__).resolve(), "release dependency freeze verifier"
        ),
    }


def _validate_binding_file_ref(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CLIENT_BINDING_FILE_KEYS:
        raise DeploymentRefused(f"{label} schema is invalid")
    if (
        not isinstance(value["path"], str)
        or not Path(value["path"]).is_absolute()
        or os.path.normpath(value["path"]) != value["path"]
        or not isinstance(value["sha256"], str)
        or not SHA256_RE.fullmatch(value["sha256"])
        or type(value["bytes"]) is not int
        or value["bytes"] <= 0
    ):
        raise DeploymentRefused(f"{label} fields are invalid")
    return value


def _verify_client_binding_ref(
    repo: Path, raw: Any, *, module: Any | None = None
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != CLIENT_BINDING_REFERENCE_KEYS:
        raise DeploymentRefused("client release binding reference schema is invalid")
    if (
        raw["schema_version"] != 1
        or raw["contract"] != CLIENT_BINDING_REFERENCE_CONTRACT
        or raw["repo_root"] != str(repo)
    ):
        raise DeploymentRefused("client release binding reference policy is invalid")
    binding = raw["binding"]
    if not isinstance(binding, dict) or set(binding) != CLIENT_BINDING_KEYS:
        raise DeploymentRefused("client release binding document schema is invalid")
    verifier = module or _load_client_binding_module()
    if (
        binding["schema_version"] != verifier.SCHEMA_VERSION
        or binding["contract"] != verifier.CONTRACT
        or binding["platform"] != verifier.PLATFORM
    ):
        raise DeploymentRefused("client release binding document contract is invalid")
    for key in ("release_input_index", "build_receipt", "artifact"):
        reference = _validate_binding_file_ref(binding[key], f"client binding {key}")
        try:
            Path(reference["path"]).relative_to(repo)
        except ValueError as exc:
            raise DeploymentRefused(
                f"client binding {key} escapes the repository"
            ) from exc
    proof_build = binding["proof_build"]
    if (
        not isinstance(proof_build, dict)
        or set(proof_build) != CLIENT_PROOF_BUILD_KEYS
        or not isinstance(proof_build.get("build_identity"), str)
        or not SHA256_RE.fullmatch(proof_build["build_identity"])
        or binding.get("build_identity")
        != f"linux:{binding.get('release')}:{proof_build['build_identity']}"
    ):
        raise DeploymentRefused("client proof build identity is invalid")
    if (
        not isinstance(raw["binding_sha256"], str)
        or not SHA256_RE.fullmatch(raw["binding_sha256"])
        or sha256_bytes(verifier.canonical_bytes(binding)) != raw["binding_sha256"]
    ):
        raise DeploymentRefused("client release binding digest is invalid")
    closure = raw["verifier_closure"]
    if not isinstance(closure, dict) or set(closure) != CLIENT_BINDING_CLOSURE_KEYS:
        raise DeploymentRefused("client release binding verifier closure is invalid")
    for key in CLIENT_BINDING_CLOSURE_KEYS:
        _validate_binding_file_ref(closure[key], f"client verifier closure {key}")
    if closure != _client_verifier_closure(verifier):
        raise DeploymentRefused("client release binding verifier closure changed")
    try:
        rebuilt = verifier.verify_client_release(
            repo,
            Path(binding["release_input_index"]["path"]),
            Path(binding["build_receipt"]["path"]),
            Path(binding["artifact"]["path"]),
            platform=verifier.PLATFORM,
        )
    except Exception as exc:
        raise DeploymentRefused(
            f"client release binding verification failed: {exc}"
        ) from exc
    if rebuilt != binding:
        raise DeploymentRefused("client release binding no longer matches exact inputs")
    return copy.deepcopy(raw)


def _verify_manifest(repo: Path, manifest_path: Path) -> tuple[dict[str, Any], str, int]:
    raw, digest, size = _load_immutable(manifest_path, "deployment inputs")
    try:
        verified = _load_manifest_module().verify_manifest(repo, manifest_path)
    except Exception as exc:
        raise DeploymentRefused(f"deployment input closure verification failed: {exc}") from exc
    if verified != raw:
        raise DeploymentRefused("deployment manifest verifier returned different data")
    return raw, digest, size


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise DeploymentRefused(f"{label} is not a SHA-256 digest")
    return value


def _created(value: Any, label: str) -> str:
    if not isinstance(value, str) or not CREATED_RE.fullmatch(value):
        raise DeploymentRefused(f"{label} is not a canonical UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DeploymentRefused(f"{label} is invalid") from exc
    return value


def _deployment_ref(path: Path, digest: str, size: int, candidate_id: str) -> dict[str, Any]:
    return {"bytes": size, "candidate_id": candidate_id, "path": str(path), "sha256": digest}


def _bounded_marker(name: str, marker: str) -> bool:
    return f"-{marker}-" in f"-{name.strip().lower().replace('_', '-')}-"


def _reserved_instance(name: str) -> bool:
    normalized = name.strip().lower().replace("_", "-")
    return normalized in RESERVED_INSTANCE_NAMES or any(
        _bounded_marker(normalized, marker) for marker in RESERVED_NAME_MARKERS
    )


def _proof_project(value: Any) -> str:
    if not isinstance(value, str) or not PROJECT_RE.fullmatch(value):
        raise DeploymentRefused("fleet project is invalid")
    normalized = value.strip().lower().replace("_", "-")
    if "proof" not in normalized or any(
        marker in normalized for marker in RESERVED_PROJECT_MARKERS
    ):
        raise DeploymentRefused(
            "executor refuses a project outside dedicated proof scope"
        )
    return value


def _gcloud_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or Path(value).name not in {"gcloud", "gcloud.cmd"}
        or ".." in value
        or not re.fullmatch(r"[A-Za-z0-9_./+-]+", value)
    ):
        raise DeploymentRefused("fleet gcloud binary path is invalid")
    return value


def _instance_map(
    fleet: Any,
) -> tuple[dict[str, dict[str, Any]], str, str, str]:
    if not isinstance(fleet, dict):
        raise DeploymentRefused("fleet schema is invalid")
    project, fleet_id, gcloud_bin = fleet.get("project"), fleet.get("fleet_id"), fleet.get("gcloud_bin")
    project = _proof_project(project)
    if not isinstance(fleet_id, str) or not FLEET_RE.fullmatch(fleet_id):
        raise DeploymentRefused("fleet id is invalid")
    gcloud_bin = _gcloud_path(gcloud_bin)
    instances = fleet.get("instances")
    if not isinstance(instances, list) or len(instances) != 3:
        raise DeploymentRefused("fleet must contain exactly three instances")
    result: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for item in instances:
        if not isinstance(item, dict):
            raise DeploymentRefused("fleet instance schema is invalid")
        role, name, zone = item.get("role"), item.get("name"), item.get("zone")
        if role not in {"control", "data-winn3", "data-cover"} or role in result:
            raise DeploymentRefused("fleet roles are missing or duplicated")
        if (
            not isinstance(name, str)
            or not GCE_NAME_RE.fullmatch(name)
            or name in names
            or _reserved_instance(name)
        ):
            raise DeploymentRefused("fleet instance name is invalid or duplicated")
        if not isinstance(zone, str) or not GCE_ZONE_RE.fullmatch(zone):
            raise DeploymentRefused("fleet zone is invalid")
        machine = item.get("machine_type")
        if not isinstance(machine, str) or not MACHINE_TYPE_RE.fullmatch(machine):
            raise DeploymentRefused("fleet machine type is invalid")
        region = item.get("region")
        if region is not None and region != zone.rsplit("-", 1)[0]:
            raise DeploymentRefused("fleet instance region does not match zone")
        result[role] = {"name": name, "zone": zone, "machine_type": machine}
        names.add(name)
    if set(result) != {"control", "data-winn3", "data-cover"}:
        raise DeploymentRefused("fleet roles are incomplete")
    return result, project, fleet_id, gcloud_bin


def _expected_installers(
    instances: Mapping[str, Mapping[str, Any]], manifest: Mapping[str, Any]
) -> list[dict[str, Any]]:
    refs = {item["path"]: item for item in manifest["installers"]}
    result: list[dict[str, Any]] = []
    for index, (role, script, flag) in enumerate(EXPECTED_STEPS):
        if script == PROOF_KEY_PROVISION_ID:
            source: Mapping[str, Any] = {
                "bytes": 0,
                "mode": 0,
                "sha256": "0" * 64,
            }
        else:
            bound = refs.get(script)
            if bound is None:
                raise DeploymentRefused(f"deployment manifest does not bind {script}")
            source = bound
        result.append(
            {
                "execution_owner": "gcp_proof_deploy.py",
                "flag": flag,
                "index": index,
                "instance": instances[role]["name"],
                "remote_mutation": True,
                "role": role,
                "script": script,
                "script_ref": {key: source[key] for key in ("bytes", "mode", "sha256")},
            }
        )
    return result


def _validate_documents(
    plan: Mapping[str, Any],
    plan_sha: str,
    apply: Mapping[str, Any],
    manifest_ref: Mapping[str, Any],
    manifest: Mapping[str, Any],
    client_release_binding: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], str, str, str, list[dict[str, Any]]]:
    plan_keys = {
        "kind", "schema_version", "phase", "created_utc", "dry_run", "fleet",
        "commands", "installers", "deployment_inputs", "client_release_binding",
    }
    apply_keys = plan_keys | {"plan_sha256"}
    if set(plan) != plan_keys or set(apply) != apply_keys:
        raise DeploymentRefused("plan or apply top-level schema is not exact v4")
    if plan["kind"] != KIND_PLAN or plan["schema_version"] != SCHEMA_VERSION or plan["phase"] != "plan" or plan["dry_run"] is not True:
        raise DeploymentRefused("plan kind, phase, version, or dry-run state is invalid")
    if apply["kind"] != KIND_APPLY or apply["schema_version"] != SCHEMA_VERSION or apply["phase"] != "apply" or apply["dry_run"] is not False:
        raise DeploymentRefused("apply kind, phase, version, or live state is invalid")
    _created(plan["created_utc"], "plan creation time")
    _created(apply["created_utc"], "apply creation time")
    if apply["plan_sha256"] != plan_sha:
        raise DeploymentRefused("apply does not bind the exact plan")
    if plan["fleet"] != apply["fleet"] or plan["commands"] != apply["commands"]:
        raise DeploymentRefused("plan and apply fleet/command bindings differ")
    if not isinstance(plan["commands"], list) or any(
        not isinstance(item, dict) or item.get("kind") == "installer" for item in plan["commands"]
    ):
        raise DeploymentRefused("caller-authored installer commands are forbidden")
    if plan["deployment_inputs"] != manifest_ref or apply["deployment_inputs"] != manifest_ref:
        raise DeploymentRefused("plan and apply do not bind the exact deployment inputs")
    if (
        plan["client_release_binding"] != client_release_binding
        or apply["client_release_binding"] != client_release_binding
    ):
        raise DeploymentRefused(
            "plan and apply do not bind the exact verified client release"
        )
    instances, project, fleet_id, gcloud_bin = _instance_map(plan["fleet"])
    installers = _expected_installers(instances, manifest)
    if plan["installers"] != installers or apply["installers"] != installers:
        raise DeploymentRefused("installer sequence is caller-authored, reordered, duplicated, skipped, or wrong-role")
    return instances, project, fleet_id, gcloud_bin, installers


@dataclass(frozen=True)
class Context:
    repo: Path
    plan_path: Path
    apply_path: Path
    manifest_path: Path
    plan: dict[str, Any]
    apply: dict[str, Any]
    manifest: dict[str, Any]
    client_release_binding: dict[str, Any]
    plan_sha256: str
    apply_sha256: str
    manifest_sha256: str
    manifest_bytes: int
    instances: dict[str, dict[str, Any]]
    project: str
    fleet_id: str
    gcloud_bin: str
    installers: list[dict[str, Any]]


def load_context(repo: Path, plan_path: Path, apply_path: Path, manifest_path: Path) -> Context:
    repository = _repo_root(repo)
    plan_file, apply_file, manifest_file = (
        _absolute_file(plan_path, "plan"),
        _absolute_file(apply_path, "apply"),
        _absolute_file(manifest_path, "deployment inputs"),
    )
    if plan_file.parent != apply_file.parent or manifest_file.parent != plan_file.parent:
        raise DeploymentRefused("plan, apply, and DEPLOYMENT_INPUTS.json must share one private state directory")
    if manifest_file.name != "DEPLOYMENT_INPUTS.json":
        raise DeploymentRefused("deployment inputs must use the exact DEPLOYMENT_INPUTS.json name")
    plan, plan_sha, _ = _load_immutable(plan_file, "plan")
    apply, apply_sha, _ = _load_immutable(apply_file, "apply")
    manifest, manifest_sha, manifest_size = _verify_manifest(repository, manifest_file)
    reference = _deployment_ref(manifest_file, manifest_sha, manifest_size, manifest["candidate_id"])
    client_release_binding = _verify_client_binding_ref(
        repository, plan.get("client_release_binding")
    )
    instances, project, fleet_id, gcloud_bin, installers = _validate_documents(
        plan,
        plan_sha,
        apply,
        reference,
        manifest,
        client_release_binding,
    )
    return Context(
        repository, plan_file, apply_file, manifest_file, plan, apply, manifest,
        client_release_binding,
        plan_sha, apply_sha, manifest_sha, manifest_size, instances, project,
        fleet_id, gcloud_bin, installers,
    )


def _read_repo_input(repo: Path, item: Mapping[str, Any]) -> bytes:
    relative = item["path"]
    pure = PurePosixPath(relative)
    if pure.is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in pure.parts):
        raise DeploymentRefused("manifest input path is unsafe")
    path = repo.joinpath(*pure.parts)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise DeploymentRefused("manifest input parent is missing") from exc
    if parent != path.parent or (repo != parent and repo not in parent.parents):
        raise DeploymentRefused("manifest input escapes through a symlink")
    data, info = _read_stable(path, f"manifest input {relative}")
    if len(data) != item["bytes"] or sha256_bytes(data) != item["sha256"] or stat.S_IMODE(info.st_mode) != item["mode"]:
        raise DeploymentRefused(f"manifest input {relative} changed")
    return data


def build_bundle(context: Context, output: Path) -> str:
    if output.exists() or output.is_symlink():
        raise DeploymentRefused("bundle output must be new")
    names = [item["path"] for item in context.manifest["inputs"]]
    if names != sorted(names) or len(names) != len(set(names)):
        raise DeploymentRefused("manifest input order is invalid")
    with output.open("xb") as stream:
        os.chmod(output, 0o600)
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for item in context.manifest["inputs"]:
                data = _read_repo_input(context.repo, item)
                info = tarfile.TarInfo(item["path"])
                info.size = len(data)
                info.mode = item["mode"]
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                archive.addfile(info, fileobj=io.BytesIO(data))
    bundle, _ = _read_stable(output, "deployment bundle")
    return sha256_bytes(bundle)


def verify_bundle(context: Context, bundle: Path, expected_sha256: str) -> None:
    data, _ = _read_stable(bundle, "deployment bundle")
    if sha256_bytes(data) != expected_sha256:
        raise DeploymentRefused("deployment bundle changed")
    expected = {item["path"]: item for item in context.manifest["inputs"]}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = archive.getmembers()
            if [item.name for item in members] != sorted(expected):
                raise DeploymentRefused("deployment bundle is not manifest-only")
            for member in members:
                item = expected.get(member.name)
                if item is None or not member.isfile() or member.issym() or member.islnk():
                    raise DeploymentRefused("deployment bundle member is unsafe")
                content = archive.extractfile(member)
                data = content.read() if content is not None else b""
                if member.uid != 0 or member.gid != 0 or member.mode != item["mode"] or len(data) != item["bytes"] or sha256_bytes(data) != item["sha256"]:
                    raise DeploymentRefused("deployment bundle member does not match the manifest")
    except (OSError, tarfile.TarError) as exc:
        raise DeploymentRefused("deployment bundle is unreadable") from exc


def verify_remote_helper(staged_helper: Path, expected_sha256: str) -> None:
    source, _ = _read_stable(REMOTE_HELPER, "remote installer helper source")
    staged, _ = _read_stable(staged_helper, "staged remote installer helper")
    if sha256_bytes(source) != expected_sha256 or sha256_bytes(staged) != expected_sha256:
        raise DeploymentRefused("remote installer helper changed")


def _capture(data: bytes) -> dict[str, Any]:
    original = len(data)
    redacted = SECRET_RE.sub(b"[REDACTED]", data)[:MAX_CAPTURE_BYTES]
    return {
        "bytes": len(redacted),
        "data": base64.b64encode(redacted).decode("ascii"),
        "encoding": "base64",
        "original_bytes": original,
        "sha256": sha256_bytes(redacted),
        "truncated": original > MAX_CAPTURE_BYTES,
    }


def _parse_remote(result: RunResult, label: str) -> dict[str, Any]:
    if len(result.stdout) > MAX_CAPTURE_BYTES or SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
        raise DeploymentRefused(f"{label} returned credential-shaped or oversized output")
    raw = strict_json(result.stdout, label)
    if not isinstance(raw, dict) or raw.get("kind") != KIND_RESPONSE or raw.get("schema_version") != 1:
        raise DeploymentRefused(f"{label} response schema is invalid")
    if canonical_bytes(raw) != result.stdout:
        raise DeploymentRefused(f"{label} response is not canonical ASCII JSON")
    _raise_if_owner_cloud_blocked(raw)
    return raw


def _raise_if_owner_cloud_blocked(payload: Mapping[str, Any]) -> None:
    refusal = payload.get("refusal")
    status = payload.get("status")
    if status == "blocked" or (
        isinstance(refusal, str) and OWNER_CLOUD_EVIDENCE_BLOCKED in refusal
    ):
        raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)


def _forbid_secret_tokens(argv: Sequence[str], label: str) -> None:
    for token in argv:
        if not isinstance(token, str):
            raise DeploymentRefused(f"{label} contains a non-string argv token")
        if token.startswith("--command="):
            continue
        if token.startswith("b64:"):
            try:
                encoded = base64.b64decode(token[4:].encode("ascii"), validate=True)
            except Exception as suc:
                raise DeploymentRefused(f"{label} contains invalid encoded stdin") from suc
        else:
            encoded = token.encode("ascii", "replace")
        if SECRET_RE.search(encoded):
            raise DeploymentRefused(f"{label} contains credential-shaped argv")


def _parse_exchange_response(result: RunResult, action: str) -> dict[str, Any]:
    if len(result.stdout) > EXCHANGE_MAX_BYTES or SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
        raise DeploymentRefused(f"{action} returned credential-shaped or oversized output")
    raw = strict_json(result.stdout, f"{action} response")
    if not isinstance(raw, dict):
        raise DeploymentRefused(f"{action} response schema is invalid")
    if raw.get("kind") == KIND_RESPONSE:
        _raise_if_owner_cloud_blocked(raw)
        if raw.get("ok") is False:
            return dict(raw)
        raise DeploymentRefused(f"{action} response schema is invalid")
    if set(raw) != EXCHANGE_RESPONSE_KEYS or raw.get("kind") != KIND_EXCHANGE_RESPONSE:
        raise DeploymentRefused(f"{action} response schema is invalid")
    if (
        raw.get("action") != action
        or raw.get("contract") != EXCHANGE_CONTRACT
        or raw.get("schema_version") != 1
        or raw.get("secret") is not None
        or canonical_bytes(raw) != result.stdout
    ):
        raise DeploymentRefused(f"{action} response is not the reviewed helper envelope")
    public = raw.get("public")
    receipt = raw.get("receipt")
    if public is not None and not isinstance(public, dict):
        raise DeploymentRefused(f"{action} public document schema is invalid")
    if receipt is not None and not isinstance(receipt, dict):
        raise DeploymentRefused(f"{action} receipt schema is invalid")
    if public and any(name in public for name in ("admission.key", "client.key", "static.key")):
        raise DeploymentRefused(f"{action} public document contains secret names")
    return dict(raw)


def _parse_runtime_probe(result: RunResult, role: str) -> dict[str, Any]:
    if SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
        raise DeploymentRefused("runtime probe returned credential-shaped output")
    raw = strict_json(result.stdout, f"runtime probe for {role}")
    if not isinstance(raw, dict) or set(raw) != RUNTIME_PROBE_KEYS:
        raise DeploymentRefused(f"runtime probe schema is invalid for {role}")
    if (
        raw.get("kind") != KIND_RUNTIME_PROBE
        or raw.get("schema_version") != 1
        or raw.get("role") != role
        or canonical_bytes(raw) != result.stdout
    ):
        raise DeploymentRefused(f"runtime probe binding is invalid for {role}")
    if raw.get("status") == "blocked":
        raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)
    if raw.get("status") != "ok":
        raise DeploymentRefused(f"runtime probe status is invalid for {role}")
    marker = raw.get("marker")
    if marker is not None and not isinstance(marker, dict):
        raise DeploymentRefused(f"runtime probe marker is invalid for {role}")
    instance_id = raw.get("instance_id")
    boot_id = raw.get("boot_id")
    if role in {EXCHANGE_SOURCE_ROLE, EXCHANGE_TARGET_ROLE}:
        if not isinstance(instance_id, str) or not GCE_ID_RE.fullmatch(instance_id):
            raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)
        if not isinstance(boot_id, str) or not BOOT_ID_RE.fullmatch(boot_id):
            raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)
    elif instance_id is not None or boot_id is not None:
        raise DeploymentRefused(f"runtime probe identity is invalid for {role}")
    return dict(raw)


def _validate_probe_marker(
    marker: Mapping[str, Any], context: Context, role: str
) -> dict[str, Any]:
    if marker.get("kind") != KIND_MARKER or marker.get("schema_version") != 1:
        raise DeploymentRefused(f"runtime probe marker kind is invalid for {role}")
    if (
        marker.get("fleet_id") != context.fleet_id
        or marker.get("role") != role
        or marker.get("instance") != context.instances[role]["name"]
        or marker.get("plan_sha256") != context.plan_sha256
        or marker.get("apply_sha256") != context.apply_sha256
        or marker.get("deployment_manifest_sha256") != context.manifest_sha256
        or marker.get("candidate_id") != context.manifest["candidate_id"]
    ):
        raise DeploymentRefused(f"runtime probe marker belongs to another target for {role}")
    indices = marker.get("completed_step_indices")
    chain = marker.get("fleet_record_chain_sha256")
    if not isinstance(indices, list) or any(type(item) is not int for item in indices):
        raise DeploymentRefused(f"runtime probe marker step list is invalid for {role}")
    if not isinstance(chain, str) or not SHA256_RE.fullmatch(chain):
        raise DeploymentRefused(f"runtime probe marker chain is invalid for {role}")
    return dict(marker)


def _skipped_step_state(
    probes: Mapping[str, Mapping[str, Any]], context: Context
) -> tuple[set[int], str]:
    completed: set[int] = set()
    chain_by_index: dict[int, str] = {}
    for role, probe in probes.items():
        marker = probe.get("marker")
        if marker is None:
            continue
        validated = _validate_probe_marker(marker, context, role)
        indices = list(validated["completed_step_indices"])
        completed.update(indices)
        if indices:
            chain_by_index[max(indices)] = str(validated["fleet_record_chain_sha256"])
    previous = ZERO_SHA256
    if chain_by_index:
        previous = chain_by_index[max(chain_by_index)]
    return completed, previous


def _exchange_machine_from_probes(
    probes: Mapping[str, Mapping[str, Any]],
    identities: Mapping[str, Any],
) -> dict[str, str]:
    instances = identities.get("instances")
    if not isinstance(instances, dict):
        raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)
    source = probes[EXCHANGE_SOURCE_ROLE]
    target = probes[EXCHANGE_TARGET_ROLE]
    source_live = instances.get(EXCHANGE_SOURCE_ROLE)
    target_live = instances.get(EXCHANGE_TARGET_ROLE)
    if not isinstance(source_live, dict) or not isinstance(target_live, dict):
        raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)
    source_id = str(source["instance_id"])
    target_id = str(target["instance_id"])
    source_boot = str(source["boot_id"])
    target_boot = str(target["boot_id"])
    source_tx = source_live.get("creation_transaction")
    target_tx = target_live.get("creation_transaction")
    if (
        not isinstance(source_tx, dict)
        or not isinstance(target_tx, dict)
        or source_tx.get("id") != source_id
        or target_tx.get("id") != target_id
    ):
        raise DeploymentRefused("GCE numeric instance id does not match authenticated describe evidence")
    if source_id == target_id or source_boot == target_boot:
        raise DeploymentRefused("authenticated key exchange v1 source and target must be distinct")
    return {
        "source_boot_id": source_boot,
        "source_instance_id": source_id,
        "target_boot_id": target_boot,
        "target_instance_id": target_id,
    }


def _record_digest(record: Mapping[str, Any]) -> str:
    core = dict(record)
    core.pop("record_sha256", None)
    return sha256_bytes(canonical_bytes(core))


def _validate_record(
    raw: Any, installer: Mapping[str, Any], context: Context, previous: str
) -> dict[str, Any]:
    keys = {
        "apply_sha256", "ended_utc", "exit_code", "flag", "fleet_id", "instance",
        "kind", "manifest_sha256", "plan_sha256", "previous_sha256", "record_sha256",
        "role", "schema_version", "script", "script_ref", "started_utc", "stderr",
        "stdout", "step_index",
    }
    if not isinstance(raw, dict) or set(raw) != keys:
        raise DeploymentRefused("remote deployment record schema is invalid")
    expected = {
        "apply_sha256": context.apply_sha256,
        "flag": installer["flag"],
        "fleet_id": context.fleet_id,
        "instance": installer["instance"],
        "kind": KIND_RECORD,
        "manifest_sha256": context.manifest_sha256,
        "plan_sha256": context.plan_sha256,
        "previous_sha256": previous,
        "role": installer["role"],
        "schema_version": 1,
        "script": installer["script"],
        "script_ref": installer["script_ref"],
        "step_index": installer["index"],
    }
    if any(raw.get(key) != value for key, value in expected.items()):
        raise DeploymentRefused("remote deployment record does not match the authenticated step")
    if type(raw["exit_code"]) is not int or not 0 <= raw["exit_code"] <= 255:
        raise DeploymentRefused("remote deployment exit code is invalid")
    _created(raw["started_utc"], "step start")
    _created(raw["ended_utc"], "step end")
    for stream in ("stdout", "stderr"):
        capture = raw[stream]
        if not isinstance(capture, dict) or set(capture) != {"bytes", "data", "encoding", "original_bytes", "sha256", "truncated"}:
            raise DeploymentRefused("remote stream capture schema is invalid")
        if capture["encoding"] != "base64" or type(capture["truncated"]) is not bool:
            raise DeploymentRefused("remote stream capture encoding is invalid")
        try:
            decoded = base64.b64decode(capture["data"], validate=True)
        except Exception as exc:
            raise DeploymentRefused("remote stream capture is not canonical base64") from exc
        if base64.b64encode(decoded).decode("ascii") != capture["data"] or capture["bytes"] != len(decoded) or capture["sha256"] != sha256_bytes(decoded) or SECRET_RE.search(decoded):
            raise DeploymentRefused("remote stream capture failed integrity or redaction checks")
    if raw["record_sha256"] != _record_digest(raw):
        raise DeploymentRefused("remote deployment record hash is invalid")
    return dict(raw)


def _validate_final_marker(
    marker: Any, context: Context, role: str, record_chain_sha256: str
) -> dict[str, Any]:
    keys = {
        "apply_sha256", "candidate_id", "completed_step_indices",
        "deployment_manifest_sha256", "fleet_completed_step_indices", "fleet_id",
        "fleet_record_chain_sha256", "instance", "kind", "plan_sha256", "role",
        "runtime", "schema_version", "updated_utc",
    }
    if not isinstance(marker, dict) or set(marker) != keys:
        raise DeploymentRefused(f"marker finalization schema is invalid for {role}")
    expected = {
        "apply_sha256": context.apply_sha256,
        "candidate_id": context.manifest["candidate_id"],
        "completed_step_indices": [index for index, item in enumerate(EXPECTED_STEPS) if item[0] == role],
        "deployment_manifest_sha256": context.manifest_sha256,
        "fleet_completed_step_indices": list(range(len(EXPECTED_STEPS))),
        "fleet_id": context.fleet_id,
        "fleet_record_chain_sha256": record_chain_sha256,
        "instance": context.instances[role]["name"],
        "kind": KIND_MARKER,
        "plan_sha256": context.plan_sha256,
        "role": role,
        "schema_version": 1,
    }
    if any(marker.get(key) != value for key, value in expected.items()):
        raise DeploymentRefused(f"marker finalization binding is invalid for {role}")
    _created(marker.get("updated_utc"), f"marker timestamp for {role}")
    runtime = marker.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {"awg", "router", "winn", "xray"}:
        raise DeploymentRefused(f"marker runtime identity schema is invalid for {role}")
    if SECRET_RE.search(canonical_bytes(runtime)):
        raise DeploymentRefused(f"marker runtime identity contains credential-shaped data for {role}")
    return dict(marker)


def _expected_labels(fleet_id: str, role: str) -> dict[str, str]:
    return {
        "winsvpn-proof-fleet": "1",
        "winsvpn-proof-id": fleet_id,
        "winsvpn-proof-role": role,
    }


def _expected_resource_labels(fleet_id: str) -> dict[str, str]:
    return {
        "winsvpn-proof-fleet": "1",
        "winsvpn-proof-id": fleet_id,
    }


def _expected_tags(fleet_id: str, role: str) -> list[str]:
    return sorted([f"pf-{fleet_id}", f"pf-role-{role}"])


def _expected_metadata(role: str) -> dict[str, str]:
    return {"enable-oslogin": "TRUE", "winsvpn-proof-role": role}


def _proof_resource_names(
    fleet_id: str, instances: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    if not isinstance(fleet_id, str) or not FLEET_RE.fullmatch(fleet_id):
        raise DeploymentRefused("fleet id is invalid")
    canonical = fleet_contract.canonical_resource_contract(
        fleet_id, {role: str(instances[role]["zone"]) for role in ROLES}
    )
    return {
        "firewalls": list(canonical["firewalls"].values()),
        "network": canonical["network"],
        "subnets": [
            {"name": item["name"], "region": item["region"]}
            for item in canonical["subnets"]
        ],
    }


def _staged_remote_paths(token: str) -> dict[str, str]:
    if not TOKEN_RE.fullmatch(token):
        raise DeploymentRefused("deployment candidate token is invalid")
    prefix = f"/tmp/winsvpn-proof-{token}"
    return {
        "bundle": f"{prefix}.tar",
        "helper": f"{prefix}-remote.py",
        "manifest": f"{prefix}-DEPLOYMENT_INPUTS.json",
        "sidecar": f"{prefix}-DEPLOYMENT_INPUTS.json.sha256",
    }


def _forbid_selection(argv: Sequence[str], label: str) -> None:
    for token in argv:
        lower = token.lower()
        if any(lower == flag or lower.startswith(flag + "=") for flag in FORBIDDEN_SELECTION_FLAGS):
            raise DeploymentRefused(f"{label} contains a broad selection flag")
        if token.startswith("--command="):
            if "\x00" in token:
                raise DeploymentRefused(f"{label} contains an unsafe token")
            continue
        if "*" in token or "\n" in token or "\x00" in token:
            raise DeploymentRefused(f"{label} contains an unsafe token")


def _strict_json_utf8(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
    except DeploymentRefused:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentRefused(f"{label} is not strict JSON") from exc


def _parse_gce_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DeploymentRefused(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DeploymentRefused(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise DeploymentRefused(f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _metadata_items(raw: Any) -> dict[str, str]:
    if not isinstance(raw, list):
        raise DeploymentRefused("instance metadata schema is invalid")
    result: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"key", "value"}:
            raise DeploymentRefused("instance metadata item schema is invalid")
        key, value = item["key"], item["value"]
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise DeploymentRefused("instance metadata keys are invalid or duplicated")
        result[key] = value
    return result


def _creation_transaction(identity: Mapping[str, Any]) -> dict[str, str]:
    raw = identity.get("creation_transaction")
    if not isinstance(raw, dict) or set(raw) != {"creation_timestamp", "id", "self_link"}:
        raise DeploymentRefused("creation transaction schema is invalid")
    if (
        not isinstance(raw["id"], str)
        or not GCE_ID_RE.fullmatch(raw["id"])
        or not isinstance(raw["creation_timestamp"], str)
        or not isinstance(raw["self_link"], str)
        or not SELF_LINK_RE.fullmatch(raw["self_link"])
    ):
        raise DeploymentRefused("creation transaction identity is invalid")
    return {
        "creation_timestamp": raw["creation_timestamp"],
        "id": raw["id"],
        "self_link": raw["self_link"],
    }


def _same_creation_identity(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    keys = (
        "fleet_id", "labels", "machine_type", "name", "project", "role", "zone",
    )
    return all(left.get(key) == right.get(key) for key in keys) and (
        _creation_transaction(left) == _creation_transaction(right)
    )


def _fingerprint(value: Any, label: str) -> str:
    if not isinstance(value, str) or not FINGERPRINT_RE.fullmatch(value):
        raise DeploymentRefused(f"{label} fingerprint is invalid")
    return value


def _resource_labels(raw: Any, fleet_id: str, label: str) -> dict[str, str]:
    if (
        not isinstance(raw, dict)
        or any(type(key) is not str or type(value) is not str for key, value in raw.items())
        or raw != _expected_resource_labels(fleet_id)
    ):
        raise DeploymentRefused(f"{label} labels are missing, extra, or not bound to this fleet")
    return dict(raw)


def _network_name_from_link(raw: Any, project: str, label: str) -> str:
    if not isinstance(raw, str):
        raise DeploymentRefused(f"{label} network identity is invalid")
    matched = NETWORK_LINK_RE.fullmatch(raw)
    if matched is None or matched.group(1) != project:
        raise DeploymentRefused(f"{label} is not bound to the exact proof network")
    return matched.group(2)


def _same_resource_identity(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    keys = (
        "fingerprint", "kind", "label_fingerprint", "labels", "name", "network",
        "project", "region", "type",
    )
    left_tx = left.get("creation_transaction")
    right_tx = right.get("creation_transaction")
    if (
        not isinstance(left_tx, dict)
        or not isinstance(right_tx, dict)
        or set(left_tx) != {"creation_timestamp", "id", "self_link"}
        or set(right_tx) != {"creation_timestamp", "id", "self_link"}
    ):
        return False
    return all(left.get(key) == right.get(key) for key in keys) and left_tx == right_tx


def _prove_named_resource(
    raw: Any,
    context: Context,
    *,
    name: str,
    resource_type: str,
    link_re: re.Pattern[str],
    now: datetime,
    apply_created: datetime,
    region: str | None = None,
    expected_network: str | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DeploymentRefused(f"live {resource_type} describe schema is invalid for {name}")
    required = {
        "creationTimestamp", "fingerprint", "id", "kind", "labelFingerprint",
        "labels", "name", "selfLink",
    }
    if not required.issubset(raw):
        raise DeploymentRefused(f"live {resource_type} describe omitted identity fields for {name}")
    if type(raw.get("id")) is not str or not GCE_ID_RE.fullmatch(raw["id"]):
        raise DeploymentRefused(f"{resource_type} creation id is invalid for {name}")
    if raw.get("name") != name or raw.get("kind") != RESOURCE_TYPES[resource_type]:
        raise DeploymentRefused(f"{resource_type} name or type is not the proof resource {name}")
    link = link_re.fullmatch(raw["selfLink"] if isinstance(raw.get("selfLink"), str) else "")
    if link is None or link.group(1) != context.project or link.group(2) != name:
        if resource_type == "subnet":
            if (
                link is None
                or link.group(1) != context.project
                or link.group(3) != name
                or region is None
                or link.group(2) != region
            ):
                raise DeploymentRefused(
                    f"{resource_type} is not bound to the exact project, region, and name for {name}"
                )
        else:
            raise DeploymentRefused(
                f"{resource_type} is not bound to the exact project and name for {name}"
            )
    labels = _resource_labels(raw.get("labels"), context.fleet_id, f"{resource_type} {name}")
    created = _parse_gce_timestamp(raw.get("creationTimestamp"), f"{resource_type} creation timestamp for {name}")
    if created <= apply_created:
        raise DeploymentRefused(f"{resource_type} is not newly created for this apply for {name}")
    if created < now - FRESHNESS_WINDOW or created > now + MAX_CLOCK_SKEW:
        raise DeploymentRefused(
            f"{resource_type} creation is outside the proof freshness window for {name}"
        )
    identity: dict[str, Any] = {
        "creation_transaction": {
            "creation_timestamp": raw["creationTimestamp"],
            "id": raw["id"],
            "self_link": raw["selfLink"],
        },
        "fingerprint": _fingerprint(raw.get("fingerprint"), f"{resource_type} {name}"),
        "kind": raw["kind"],
        "label_fingerprint": _fingerprint(
            raw.get("labelFingerprint"), f"{resource_type} {name} label"
        ),
        "labels": labels,
        "name": name,
        "project": context.project,
        "type": resource_type,
    }
    if resource_type in {"firewall", "subnet"}:
        parent = _network_name_from_link(raw.get("network"), context.project, f"{resource_type} {name}")
        if expected_network is not None and parent != expected_network:
            raise DeploymentRefused(f"{resource_type} {name} is not attached to this fleet network")
        identity["network"] = parent
    if resource_type == "subnet":
        zone_or_region = raw.get("region")
        if isinstance(zone_or_region, str) and not zone_or_region.startswith("http"):
            observed_region = zone_or_region
        else:
            region_link = REGION_LINK_RE.fullmatch(
                zone_or_region if isinstance(zone_or_region, str) else ""
            )
            if region_link is None or region_link.group(1) != context.project:
                raise DeploymentRefused(f"subnet region identity is invalid for {name}")
            observed_region = region_link.group(2)
        if region is None or observed_region != region:
            raise DeploymentRefused(f"subnet is not bound to the exact region for {name}")
        identity["region"] = observed_region
    if resource_type == "network":
        if raw.get("autoCreateSubnetworks") is not False:
            raise DeploymentRefused(f"network {name} is not a custom proof VPC")
        routing = raw.get("routingConfig")
        mode = routing.get("routingMode") if isinstance(routing, dict) else raw.get("routingMode")
        if mode != "REGIONAL":
            raise DeploymentRefused(f"network {name} is not regional proof routing")
    return identity


def _prove_fresh_instance(
    raw: Any,
    context: Context,
    role: str,
    *,
    now: datetime,
    apply_created: datetime,
) -> dict[str, Any]:
    instance = context.instances[role]
    if not isinstance(raw, dict):
        raise DeploymentRefused(f"live instance describe schema is invalid for {role}")
    required = {
        "creationTimestamp", "deletionProtection", "id", "labels", "machineType",
        "metadata", "name", "selfLink", "status", "tags", "zone",
    }
    if not required.issubset(raw):
        raise DeploymentRefused(f"live instance describe omitted identity fields for {role}")
    if type(raw.get("id")) is not str or not GCE_ID_RE.fullmatch(raw["id"]):
        raise DeploymentRefused(f"instance creation id is invalid for {role}")
    if raw.get("name") != instance["name"] or raw.get("status") != "RUNNING":
        raise DeploymentRefused(f"instance name or power state is not the fresh proof VM for {role}")
    link = SELF_LINK_RE.fullmatch(raw["selfLink"] if isinstance(raw.get("selfLink"), str) else "")
    zone = ZONE_LINK_RE.fullmatch(raw["zone"] if isinstance(raw.get("zone"), str) else "")
    machine = MACHINE_LINK_RE.fullmatch(
        raw["machineType"] if isinstance(raw.get("machineType"), str) else ""
    )
    if link is None or zone is None or machine is None:
        raise DeploymentRefused(f"instance project, zone, or machine identity is invalid for {role}")
    project, link_zone, link_name = link.group(1), link.group(2), link.group(3)
    if (
        project != context.project
        or zone.group(1) != context.project
        or machine.group(1) != context.project
        or link_zone != instance["zone"]
        or zone.group(2) != instance["zone"]
        or machine.group(2) != instance["zone"]
        or link_name != instance["name"]
        or machine.group(3) != instance["machine_type"]
    ):
        raise DeploymentRefused(
            f"instance is not bound to the exact project, zone, and machine identity for {role}"
        )
    labels = raw.get("labels")
    if (
        not isinstance(labels, dict)
        or any(type(key) is not str or type(value) is not str for key, value in labels.items())
        or labels != _expected_labels(context.fleet_id, role)
    ):
        raise DeploymentRefused(f"instance labels are missing, extra, or not bound to this fleet for {role}")
    tags = raw.get("tags")
    items = tags.get("items") if isinstance(tags, dict) else None
    if not isinstance(items, list) or any(type(item) is not str for item in items):
        raise DeploymentRefused(f"instance tags are invalid for {role}")
    if sorted(items) != _expected_tags(context.fleet_id, role):
        raise DeploymentRefused(f"instance tags are not bound to this fleet for {role}")
    if raw.get("deletionProtection") is not True:
        raise DeploymentRefused(f"instance is not a clean undeployed proof VM for {role}")
    expected_forwarding = role in {"data-winn3", "data-cover"}
    if (
        type(raw.get("canIpForward")) is not bool
        or raw["canIpForward"] is not expected_forwarding
    ):
        raise DeploymentRefused(
            f"instance canIpForward does not match the exact role for {role}"
        )
    metadata = raw.get("metadata")
    metadata_items = metadata.get("items") if isinstance(metadata, dict) else None
    if _metadata_items(metadata_items) != _expected_metadata(role):
        raise DeploymentRefused(
            f"instance metadata shows reuse or a partial deployment for {role}"
        )
    accounts = raw.get("serviceAccounts", [])
    if accounts is None:
        accounts = []
    if type(accounts) is not list or accounts:
        raise DeploymentRefused(f"instance has attached identities and is not a clean proof VM for {role}")
    shielded = raw.get("shieldedInstanceConfig")
    if not isinstance(shielded, dict) or any(
        shielded.get(key) is not True
        for key in ("enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring")
    ):
        raise DeploymentRefused(f"instance shielded identity is not a clean proof VM for {role}")
    created = _parse_gce_timestamp(raw.get("creationTimestamp"), f"creation timestamp for {role}")
    if created <= apply_created:
        raise DeploymentRefused(f"instance is not newly created for this apply for {role}")
    if created < now - FRESHNESS_WINDOW or created > now + MAX_CLOCK_SKEW:
        raise DeploymentRefused(f"instance creation is outside the proof freshness window for {role}")
    return {
        "creation_transaction": {
            "creation_timestamp": raw["creationTimestamp"],
            "id": raw["id"],
            "self_link": raw["selfLink"],
        },
        "can_ip_forward": expected_forwarding,
        "fleet_id": context.fleet_id,
        "labels": dict(labels),
        "machine_type": instance["machine_type"],
        "name": instance["name"],
        "project": context.project,
        "role": role,
        "zone": instance["zone"],
    }


def _fixed_describe(context: Context, role: str) -> list[str]:
    instance = context.instances[role]
    argv = [
        context.gcloud_bin, "compute", "instances", "describe", instance["name"],
        f"--project={context.project}", f"--zone={instance['zone']}", DESCRIBE_FORMAT,
    ]
    _forbid_selection(argv, "instance describe")
    return argv


def _fixed_describe_firewall(context: Context, name: str) -> list[str]:
    if not GCE_NAME_RE.fullmatch(name) or not name.startswith(f"pf-{context.fleet_id}-"):
        raise DeploymentRefused("firewall describe target is not this fleet's exact resource")
    argv = [
        context.gcloud_bin, "compute", "firewall-rules", "describe", name,
        f"--project={context.project}", FIREWALL_DESCRIBE_FORMAT,
    ]
    _forbid_selection(argv, "firewall describe")
    return argv


def _fixed_describe_subnet(context: Context, name: str, region: str) -> list[str]:
    if (
        not GCE_NAME_RE.fullmatch(name)
        or not name.startswith(f"pf-{context.fleet_id}-")
        or not re.fullmatch(r"[a-z]+-[a-z]+[0-9]+\Z", region)
    ):
        raise DeploymentRefused("subnet describe target is not this fleet's exact resource")
    argv = [
        context.gcloud_bin, "compute", "networks", "subnets", "describe", name,
        f"--project={context.project}", f"--region={region}", SUBNET_DESCRIBE_FORMAT,
    ]
    _forbid_selection(argv, "subnet describe")
    return argv


def _fixed_describe_network(context: Context, name: str) -> list[str]:
    expected = f"pf-{context.fleet_id}-net"
    if name != expected or not GCE_NAME_RE.fullmatch(name):
        raise DeploymentRefused("network describe target is not this fleet's exact resource")
    argv = [
        context.gcloud_bin, "compute", "networks", "describe", name,
        f"--project={context.project}", NETWORK_DESCRIBE_FORMAT,
    ]
    _forbid_selection(argv, "network describe")
    return argv


def _describe_json(runner: Runner, argv: Sequence[str], label: str) -> Any:
    result = runner.run(list(argv), timeout_seconds=60)
    if result.exit_code != 0 or len(result.stdout) > MAX_CAPTURE_BYTES:
        raise DeploymentRefused(f"{label} failed")
    if SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
        raise DeploymentRefused(f"{label} returned credential-shaped output")
    return _strict_json_utf8(result.stdout, label)


def _describe_and_prove(
    context: Context,
    runner: Runner,
    role: str,
    *,
    now: datetime,
    apply_created: datetime,
) -> dict[str, Any]:
    raw = _describe_json(runner, _fixed_describe(context, role), f"live instance describe for {role}")
    return _prove_fresh_instance(
        raw, context, role, now=now, apply_created=apply_created
    )


def _describe_and_prove_firewall(
    context: Context,
    runner: Runner,
    name: str,
    *,
    now: datetime,
    apply_created: datetime,
    expected_network: str,
) -> dict[str, Any]:
    raw = _describe_json(
        runner,
        _fixed_describe_firewall(context, name),
        f"live firewall describe for {name}",
    )
    return _prove_named_resource(
        raw,
        context,
        name=name,
        resource_type="firewall",
        link_re=FIREWALL_LINK_RE,
        now=now,
        apply_created=apply_created,
        expected_network=expected_network,
    )


def _describe_and_prove_subnet(
    context: Context,
    runner: Runner,
    name: str,
    region: str,
    *,
    now: datetime,
    apply_created: datetime,
    expected_network: str,
) -> dict[str, Any]:
    raw = _describe_json(
        runner,
        _fixed_describe_subnet(context, name, region),
        f"live subnet describe for {name}",
    )
    return _prove_named_resource(
        raw,
        context,
        name=name,
        resource_type="subnet",
        link_re=SUBNET_LINK_RE,
        now=now,
        apply_created=apply_created,
        region=region,
        expected_network=expected_network,
    )


def _describe_and_prove_network(
    context: Context,
    runner: Runner,
    name: str,
    *,
    now: datetime,
    apply_created: datetime,
) -> dict[str, Any]:
    raw = _describe_json(
        runner,
        _fixed_describe_network(context, name),
        f"live network describe for {name}",
    )
    return _prove_named_resource(
        raw,
        context,
        name=name,
        resource_type="network",
        link_re=NETWORK_LINK_RE,
        now=now,
        apply_created=apply_created,
    )


def _empty_preflight() -> dict[str, Any]:
    return {"firewalls": {}, "instances": {}, "network": {}, "subnets": {}}


def _preflight_identities(
    context: Context, runner: Runner, *, now: datetime, apply_created: datetime
) -> dict[str, Any]:
    identities = _empty_preflight()
    seen_ids: set[str] = set()
    seen_links: set[str] = set()

    def remember(identity: Mapping[str, Any], label: str) -> None:
        transaction = identity["creation_transaction"]
        if transaction["id"] in seen_ids or transaction["self_link"] in seen_links:
            raise DeploymentRefused(f"proof {label} creation identity is duplicated")
        seen_ids.add(transaction["id"])
        seen_links.add(transaction["self_link"])

    for role in ROLES:
        identity = _describe_and_prove(
            context, runner, role, now=now, apply_created=apply_created
        )
        remember(identity, "instance")
        identities["instances"][role] = identity
    names = _proof_resource_names(context.fleet_id, context.instances)
    network_name = names["network"]
    for firewall in names["firewalls"]:
        identity = _describe_and_prove_firewall(
            context,
            runner,
            firewall,
            now=now,
            apply_created=apply_created,
            expected_network=network_name,
        )
        remember(identity, "firewall")
        identities["firewalls"][firewall] = identity
    for subnet in names["subnets"]:
        identity = _describe_and_prove_subnet(
            context,
            runner,
            subnet["name"],
            subnet["region"],
            now=now,
            apply_created=apply_created,
            expected_network=network_name,
        )
        remember(identity, "subnet")
        identities["subnets"][subnet["name"]] = identity
    identities["network"] = _describe_and_prove_network(
        context, runner, network_name, now=now, apply_created=apply_created
    )
    remember(identities["network"], "network")
    return identities


def _preflight_complete(context: Context, preflight: Mapping[str, Any]) -> bool:
    names = _proof_resource_names(context.fleet_id, context.instances)
    instances = preflight.get("instances")
    firewalls = preflight.get("firewalls")
    subnets = preflight.get("subnets")
    network = preflight.get("network")
    if not isinstance(instances, dict) or set(instances) != set(ROLES):
        return False
    if not isinstance(firewalls, dict) or set(firewalls) != set(names["firewalls"]):
        return False
    expected_subnets = {item["name"] for item in names["subnets"]}
    if not isinstance(subnets, dict) or set(subnets) != expected_subnets:
        return False
    return isinstance(network, dict) and network.get("name") == names["network"]


def _preflight_view(identities: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(identities, dict) or set(identities) != PREFLIGHT_KEYS:
        return _empty_preflight()
    return {
        "firewalls": copy.deepcopy(dict(identities.get("firewalls") or {})),
        "instances": copy.deepcopy(dict(identities.get("instances") or {})),
        "network": copy.deepcopy(dict(identities.get("network") or {})),
        "subnets": copy.deepcopy(dict(identities.get("subnets") or {})),
    }


def _fixed_scp(
    context: Context, instance: Mapping[str, Any], sources: Sequence[Path]
) -> list[str]:
    argv = [
        context.gcloud_bin, "compute", "scp", *(str(item) for item in sources),
        f"{instance['name']}:/tmp", f"--project={context.project}",
        f"--zone={instance['zone']}", "--quiet",
    ]
    _forbid_selection(argv, "instance copy")
    return argv


def _remote_base_args(context: Context, staged: Mapping[str, str], role: str, previous: str) -> list[str]:
    instance = context.instances[role]
    fleet_binding = {
        "schema_version": 1,
        "contract": "winsvpn-gcp-proof-fleet-binding-v1",
        "project": context.project,
        "fleet_id": context.fleet_id,
        "control": {
            "instance": context.instances["control"]["name"],
            "zone": context.instances["control"]["zone"],
        },
        "data-winn3": {
            "instance": context.instances["data-winn3"]["name"],
            "zone": context.instances["data-winn3"]["zone"],
        },
        "data-cover": {
            "instance": context.instances["data-cover"]["name"],
            "zone": context.instances["data-cover"]["zone"],
        },
    }
    return [
        "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", REMOTE_HELPER_BOOTSTRAP,
        staged["helper"], staged["helper_sha256"],
        "--bundle", staged["bundle"], "--bundle-sha256", staged["bundle_sha256"],
        "--manifest", staged["manifest"], "--manifest-sidecar", staged["sidecar"],
        "--manifest-sha256", context.manifest_sha256,
        "--helper-sha256", staged["helper_sha256"],
        "--plan-sha256", context.plan_sha256, "--apply-sha256", context.apply_sha256,
        "--fleet-id", context.fleet_id,
        "--fleet-binding-json", json.dumps(fleet_binding, sort_keys=True, separators=(",", ":")),
        "--role", role, "--instance", instance["name"],
        "--previous-record-sha256", previous,
        "--marker", REMOTE_MARKER, "--state-root", REMOTE_STATE,
    ]


def _fixed_ssh(context: Context, role: str, remote_argv: Sequence[str]) -> list[str]:
    _forbid_secret_tokens(remote_argv, "instance ssh remote")
    instance = context.instances[role]
    argv = [
        context.gcloud_bin, "compute", "ssh", instance["name"],
        f"--project={context.project}", f"--zone={instance['zone']}", "--quiet",
        f"--command={shlex.join(remote_argv)}",
    ]
    _forbid_selection(argv, "instance ssh")
    _forbid_secret_tokens(argv, "instance ssh")
    return argv


def _runtime_probe_args(role: str) -> list[str]:
    if role not in ROLES:
        raise DeploymentRefused("runtime probe role is invalid")
    argv = [
        "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
        REMOTE_RUNTIME_PROBE_BOOTSTRAP, role,
    ]
    _forbid_secret_tokens(argv, "runtime probe")
    return argv


def _remote_exchange_args(
    context: Context,
    staged: Mapping[str, str],
    role: str,
    previous: str,
    action: str,
    machine: Mapping[str, str],
    *,
    stdin_mode: str,
    stdout_mode: str,
) -> list[str]:
    if action not in EXCHANGE_ACTIONS:
        raise DeploymentRefused("authenticated key exchange v1 action is invalid")
    if role not in {EXCHANGE_SOURCE_ROLE, EXCHANGE_TARGET_ROLE}:
        raise DeploymentRefused("authenticated key exchange v1 role is invalid")
    if stdout_mode not in {"helper", "pipe-consumer"}:
        raise DeploymentRefused("exchange stdout mode is invalid")
    if stdin_mode not in {"none", "pipe"} and not stdin_mode.startswith("b64:"):
        raise DeploymentRefused("exchange stdin mode is invalid")
    instance = context.instances[role]
    fleet_binding = {
        "schema_version": 1,
        "contract": "winsvpn-gcp-proof-fleet-binding-v1",
        "project": context.project,
        "fleet_id": context.fleet_id,
        "control": {
            "instance": context.instances["control"]["name"],
            "zone": context.instances["control"]["zone"],
        },
        "data-winn3": {
            "instance": context.instances["data-winn3"]["name"],
            "zone": context.instances["data-winn3"]["zone"],
        },
        "data-cover": {
            "instance": context.instances["data-cover"]["name"],
            "zone": context.instances["data-cover"]["zone"],
        },
    }
    argv = [
        "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
        REMOTE_EXCHANGE_BOOTSTRAP,
        staged["helper"], staged["helper_sha256"], stdin_mode, stdout_mode,
        "--bundle", staged["bundle"], "--bundle-sha256", staged["bundle_sha256"],
        "--manifest", staged["manifest"], "--manifest-sidecar", staged["sidecar"],
        "--manifest-sha256", context.manifest_sha256,
        "--helper-sha256", staged["helper_sha256"],
        "--plan-sha256", context.plan_sha256, "--apply-sha256", context.apply_sha256,
        "--fleet-id", context.fleet_id,
        "--fleet-binding-json", json.dumps(fleet_binding, sort_keys=True, separators=(",", ":")),
        "--role", role, "--instance", instance["name"],
        "--previous-record-sha256", previous,
        "--marker", REMOTE_MARKER, "--state-root", REMOTE_STATE,
        "--action", action,
        "--candidate-id", str(context.manifest["candidate_id"]),
        "--source-role", EXCHANGE_SOURCE_ROLE,
        "--source-instance", context.instances[EXCHANGE_SOURCE_ROLE]["name"],
        "--target-role", EXCHANGE_TARGET_ROLE,
        "--target-instance", context.instances[EXCHANGE_TARGET_ROLE]["name"],
        "--source-instance-id", machine["source_instance_id"],
        "--target-instance-id", machine["target_instance_id"],
        "--source-boot-id", machine["source_boot_id"],
        "--target-boot-id", machine["target_boot_id"],
        "--inner-v4", PROOF_CLIENT_INNER_V4,
    ]
    _forbid_secret_tokens(argv, f"{action} argv")
    return argv


def _peer_stdin_mode(payload: Mapping[str, Any]) -> str:
    data = canonical_bytes(payload)
    if len(data) > EXCHANGE_MAX_BYTES or SECRET_RE.search(data):
        raise DeploymentRefused("authenticated key exchange v1 peer document is unsafe")
    if payload.get("secret") is not None:
        raise DeploymentRefused("authenticated key exchange v1 peer document contains secret material")
    return "b64:" + base64.b64encode(data).decode("ascii")


def _exchange_public_producer_args() -> list[str]:
    argv = [
        "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
        REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP,
    ]
    _forbid_secret_tokens(argv, "exchange public producer")
    return argv


def _run_ssh_command(
    context: Context,
    runner: Runner,
    role: str,
    remote_argv: Sequence[str],
    *,
    timeout_seconds: int,
) -> RunResult:
    argv = _fixed_ssh(context, role, remote_argv)
    return runner.run(argv, timeout_seconds=timeout_seconds)


def _run_authenticated_ssh_pipe(
    context: Context,
    runner: Runner,
    producer_role: str,
    producer_remote: Sequence[str],
    consumer_role: str,
    consumer_remote: Sequence[str],
    *,
    timeout_seconds: int,
) -> RunResult:
    method = getattr(runner, "run_ssh_pipe", None)
    if not callable(method):
        raise DeploymentRefused(
            "authenticated SSH pipe is required for control/data secret exchange"
        )
    producer = _fixed_ssh(context, producer_role, producer_remote)
    consumer = _fixed_ssh(context, consumer_role, consumer_remote)
    try:
        result = method(
            producer,
            consumer,
            timeout_seconds=timeout_seconds,
            consumer_response_validator=gcloud_custody.validate_ssh_pipe_consumer_response,
        )
    except gcloud_custody.GcloudCustodyError as suc:
        raise DeploymentRefused("authenticated key exchange v1 SSH pipe failed") from suc
    stdout = bytes(getattr(result, "stdout", b""))
    stderr = bytes(getattr(result, "stderr", b""))
    exit_code = int(getattr(result, "exit_code", 1))
    if SECRET_RE.search(stdout) or SECRET_RE.search(stderr):
        raise DeploymentRefused("SSH pipe returned credential-shaped output")
    if exit_code != 0:
        raise DeploymentRefused("authenticated key exchange v1 SSH pipe failed")
    try:
        gcloud_custody.validate_ssh_pipe_consumer_response(stdout)
    except gcloud_custody.GcloudCustodyError as suc:
        raise DeploymentRefused("authenticated key exchange v1 SSH pipe receipt is invalid") from suc
    return RunResult(stdout, stderr, exit_code)


def _try_exchange_status(
    context: Context,
    runner: Runner,
    staged: Mapping[str, str],
    previous: str,
    role: str,
    machine: Mapping[str, str],
) -> dict[str, Any] | None:
    remote = _remote_exchange_args(
        context, staged, role, previous, "exchange-status", machine,
        stdin_mode="none", stdout_mode="helper",
    )
    result = _run_ssh_command(context, runner, role, remote, timeout_seconds=300)
    parsed = _parse_exchange_response(result, "exchange-status")
    if parsed.get("kind") == KIND_RESPONSE:
        return None
    receipt = parsed.get("receipt")
    if not isinstance(receipt, dict):
        raise DeploymentRefused("exchange-status receipt is invalid")
    completed = receipt.get("completed_actions")
    sealed = receipt.get("sealed")
    if not isinstance(completed, list) or type(sealed) is not bool:
        raise DeploymentRefused("exchange-status receipt schema is invalid")
    if any(not isinstance(item, str) for item in completed):
        raise DeploymentRefused("exchange-status completed actions are invalid")
    return {"completed_actions": list(completed), "sealed": sealed}


def _run_exchange_helper(
    context: Context,
    runner: Runner,
    staged: Mapping[str, str],
    previous: str,
    role: str,
    action: str,
    machine: Mapping[str, str],
    *,
    peer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    stdin_mode = "none" if peer is None else _peer_stdin_mode(peer)
    remote = _remote_exchange_args(
        context, staged, role, previous, action, machine,
        stdin_mode=stdin_mode, stdout_mode="helper",
    )
    result = _run_ssh_command(context, runner, role, remote, timeout_seconds=300)
    parsed = _parse_exchange_response(result, action)
    if parsed.get("kind") == KIND_RESPONSE:
        refusal = parsed.get("refusal")
        if isinstance(refusal, str) and OWNER_CLOUD_EVIDENCE_BLOCKED in refusal:
            raise DeploymentBlocked(OWNER_CLOUD_EVIDENCE_BLOCKED)
        raise DeploymentRefused(f"{action} was refused")
    return parsed


def _run_control_data_exchange(
    context: Context,
    runner: Runner,
    staged: Mapping[str, str],
    previous: str,
    machine: Mapping[str, str],
) -> None:
    control_status = _try_exchange_status(
        context, runner, staged, previous, EXCHANGE_TARGET_ROLE, machine
    )
    data_status = _try_exchange_status(
        context, runner, staged, previous, EXCHANGE_SOURCE_ROLE, machine
    )
    control_sealed = bool(control_status and control_status.get("sealed") is True)
    data_sealed = bool(data_status and data_status.get("sealed") is True)
    if control_sealed and data_sealed:
        return
    control_started = bool(control_status and control_status.get("completed_actions"))
    data_started = bool(data_status and data_status.get("completed_actions"))
    if control_started or data_started:
        raise DeploymentRefused(
            "partial authenticated key exchange v1 must be rolled back before retry"
        )
    control_id = _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_TARGET_ROLE, "exchange-identity", machine
    )
    data_id = _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_SOURCE_ROLE, "exchange-identity", machine
    )
    _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_TARGET_ROLE, "exchange-challenge",
        machine, peer=data_id,
    )
    data_challenge = _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_SOURCE_ROLE, "exchange-challenge",
        machine, peer=control_id,
    )
    offer = _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_TARGET_ROLE, "exchange-control-offer",
        machine, peer=data_challenge,
    )
    _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_SOURCE_ROLE, "exchange-data-accept",
        machine, peer=offer,
    )
    emit_remote = _remote_exchange_args(
        context, staged, EXCHANGE_SOURCE_ROLE, previous, "exchange-data-emit", machine,
        stdin_mode="none", stdout_mode="helper",
    )
    import_remote = _remote_exchange_args(
        context, staged, EXCHANGE_TARGET_ROLE, previous, "exchange-control-import", machine,
        stdin_mode="pipe", stdout_mode="pipe-consumer",
    )
    _run_authenticated_ssh_pipe(
        context, runner, EXCHANGE_SOURCE_ROLE, emit_remote,
        EXCHANGE_TARGET_ROLE, import_remote, timeout_seconds=300,
    )
    consume_remote = _remote_exchange_args(
        context, staged, EXCHANGE_SOURCE_ROLE, previous, "exchange-data-consume", machine,
        stdin_mode="pipe", stdout_mode="pipe-consumer",
    )
    _run_authenticated_ssh_pipe(
        context, runner, EXCHANGE_TARGET_ROLE, _exchange_public_producer_args(),
        EXCHANGE_SOURCE_ROLE, consume_remote, timeout_seconds=300,
    )
    _run_exchange_helper(
        context, runner, staged, previous, EXCHANGE_TARGET_ROLE, "exchange-control-seal",
        machine,
    )
    control_done = _try_exchange_status(
        context, runner, staged, previous, EXCHANGE_TARGET_ROLE, machine
    )
    data_done = _try_exchange_status(
        context, runner, staged, previous, EXCHANGE_SOURCE_ROLE, machine
    )
    if (
        control_done is None
        or data_done is None
        or control_done.get("sealed") is not True
        or data_done.get("sealed") is not True
    ):
        raise DeploymentRefused("authenticated key exchange v1 did not seal")


def _control_deployment_observation_spec(context: Context) -> dict[str, Any]:
    broker = context.manifest.get("attempt_broker")
    helper = context.manifest.get("remote_action_helper")
    if not isinstance(broker, dict) or not isinstance(helper, dict):
        raise DeploymentRefused("control deployment observation binding is missing")

    def bound_file(item: Mapping[str, Any], *, mode: int | None = None) -> dict[str, Any]:
        required = ("bytes", "install_path", "sha256")
        if any(key not in item for key in required):
            raise DeploymentRefused("control deployment observation file binding is incomplete")
        value = {
            "bytes": item["bytes"],
            "mode": item.get("mode") if mode is None else mode,
            "path": item["install_path"],
            "sha256": item["sha256"],
        }
        if (
            type(value["bytes"]) is not int
            or value["bytes"] < 0
            or type(value["mode"]) is not int
            or not isinstance(value["path"], str)
            or not value["path"].startswith("/")
            or not isinstance(value["sha256"], str)
            or SHA256_RE.fullmatch(value["sha256"]) is None
        ):
            raise DeploymentRefused("control deployment observation file binding is invalid")
        return value

    files = [
        bound_file(helper, mode=0o555),
        bound_file(broker, mode=0o555),
        bound_file(broker["socket"], mode=0o444),
        bound_file(broker["service"], mode=0o444),
        *(bound_file(item, mode=0o444) for item in broker["units"]),
        *(bound_file(item, mode=0o400) for item in broker["configs"]),
    ]
    proof_matches = [
        item for item in context.manifest.get("proof_client_artifacts", [])
        if isinstance(item, dict) and item.get("product") == "winn3-probe"
    ]
    if len(proof_matches) != 1:
        raise DeploymentRefused("control proof-client observation binding is incomplete")
    proof = dict(proof_matches[0])
    proof_inputs = [
        item for item in context.manifest.get("inputs", [])
        if isinstance(item, dict) and item.get("path") == proof.get("path")
    ]
    if len(proof_inputs) != 1:
        raise DeploymentRefused("control proof-client input binding is incomplete")
    proof["bytes"] = proof_inputs[0]["bytes"]
    proof["mode"] = proof_inputs[0]["mode"]
    proof["install_path"] = "/usr/local/bin/winn3-probe"
    files.append(bound_file(proof))
    runtime_paths = {
        "amneziawg-go": "/usr/local/bin/amneziawg-go",
        "awg": "/usr/local/bin/awg",
        "xray": "/usr/local/bin/xray",
    }
    runtimes = context.manifest.get("client_runtime_artifacts")
    if not isinstance(runtimes, list) or {
        item.get("product") for item in runtimes if isinstance(item, dict)
    } != set(runtime_paths):
        raise DeploymentRefused("control client-runtime observation binding is incomplete")
    for product in sorted(runtime_paths):
        matches = [item for item in runtimes if item.get("product") == product]
        if len(matches) != 1:
            raise DeploymentRefused("control client-runtime observation binding is duplicated")
        item = dict(matches[0])
        item["install_path"] = runtime_paths[product]
        files.append(bound_file(item))
    role_data = b"control\n"
    fleet_binding = {
        "schema_version": 1,
        "contract": "winsvpn-gcp-proof-fleet-binding-v1",
        "project": context.project,
        "fleet_id": context.fleet_id,
        **{
            role: {
                "instance": context.instances[role]["name"],
                "zone": context.instances[role]["zone"],
            }
            for role in ROLES
        },
    }
    fleet_data = canonical_bytes(fleet_binding)
    files.extend(
        [
            {
                "bytes": len(role_data),
                "mode": 0o400,
                "path": "/etc/winsvpn/role",
                "sha256": sha256_bytes(role_data),
            },
            {
                "bytes": len(fleet_data),
                "mode": 0o400,
                "path": "/var/lib/winsvpn-proof/fleet-binding.json",
                "sha256": sha256_bytes(fleet_data),
            },
        ]
    )
    paths = [item["path"] for item in files]
    if len(paths) != len(set(paths)):
        raise DeploymentRefused("control deployment observation paths are duplicated")
    return {
        "client_units": [item["name"] for item in broker["units"]],
        "files": files,
        "role": "control",
        "service": broker["service"]["name"],
        "socket": broker["socket"]["name"],
    }


def _parse_control_deployment_observation(
    result: RunResult, spec: Mapping[str, Any]
) -> dict[str, Any]:
    if (
        result.exit_code != 0
        or result.stderr
        or len(result.stdout) > MAX_CAPTURE_BYTES
        or SECRET_RE.search(result.stdout)
    ):
        raise DeploymentRefused("control deployment observation failed")
    raw = strict_json(result.stdout, "control deployment observation")
    expected_keys = {
        "client_units_verified", "files_verified", "kind", "role",
        "schema_version", "service", "socket",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != expected_keys
        or raw.get("kind") != KIND_DEPLOYMENT_OBSERVATION
        or raw.get("schema_version") != 1
        or raw.get("role") != "control"
        or canonical_bytes(raw) != result.stdout
        or raw.get("client_units_verified") != spec["client_units"]
        or raw.get("files_verified") != [item["path"] for item in spec["files"]]
    ):
        raise DeploymentRefused("control deployment observation schema is invalid")
    state_keys = {"active", "enabled", "failed", "installed", "name"}
    service = raw.get("service")
    socket = raw.get("socket")
    if (
        not isinstance(service, dict)
        or set(service) != state_keys
        or service.get("name") != spec["service"]
        or type(service.get("active")) is not bool
        or type(service.get("enabled")) is not bool
        or service.get("failed") is not False
        or service.get("installed") is not True
        or not isinstance(socket, dict)
        or set(socket) != state_keys
        or socket.get("name") != spec["socket"]
        or socket.get("active") is not True
        or socket.get("enabled") is not True
        or socket.get("failed") is not False
        or socket.get("installed") is not True
    ):
        raise DeploymentRefused("control deployment systemd observation is invalid")
    return dict(raw)


def _fixed_update_no_protection(context: Context, role: str) -> list[str]:
    instance = context.instances[role]
    argv = [
        context.gcloud_bin, "compute", "instances", "update", instance["name"],
        f"--project={context.project}", f"--zone={instance['zone']}",
        "--no-deletion-protection", "--quiet",
    ]
    _forbid_selection(argv, "instance update")
    return argv


def _fixed_delete_instance(context: Context, role: str) -> list[str]:
    instance = context.instances[role]
    argv = [
        context.gcloud_bin, "compute", "instances", "delete", instance["name"],
        f"--project={context.project}", f"--zone={instance['zone']}", "--quiet",
    ]
    _forbid_selection(argv, "instance delete")
    return argv


def _fixed_delete_firewall(context: Context, name: str) -> list[str]:
    if not GCE_NAME_RE.fullmatch(name) or not name.startswith(f"pf-{context.fleet_id}-"):
        raise DeploymentRefused("firewall cleanup target is not this fleet's exact resource")
    argv = [
        context.gcloud_bin, "compute", "firewall-rules", "delete", name,
        f"--project={context.project}", "--quiet",
    ]
    _forbid_selection(argv, "firewall delete")
    return argv


def _fixed_delete_subnet(context: Context, name: str, region: str) -> list[str]:
    if (
        not GCE_NAME_RE.fullmatch(name)
        or not name.startswith(f"pf-{context.fleet_id}-")
        or not re.fullmatch(r"[a-z]+-[a-z]+[0-9]+\Z", region)
    ):
        raise DeploymentRefused("subnet cleanup target is not this fleet's exact resource")
    argv = [
        context.gcloud_bin, "compute", "networks", "subnets", "delete", name,
        f"--project={context.project}", f"--region={region}", "--quiet",
    ]
    _forbid_selection(argv, "subnet delete")
    return argv


def _fixed_delete_network(context: Context, name: str) -> list[str]:
    expected = f"pf-{context.fleet_id}-net"
    if name != expected or not GCE_NAME_RE.fullmatch(name):
        raise DeploymentRefused("network cleanup target is not this fleet's exact resource")
    argv = [
        context.gcloud_bin, "compute", "networks", "delete", name,
        f"--project={context.project}", "--quiet",
    ]
    _forbid_selection(argv, "network delete")
    return argv


def _command_result(command: str, result: RunResult, **extra: Any) -> dict[str, Any]:
    payload = {
        "command": command,
        "exit_code": result.exit_code,
        "stderr": _capture(result.stderr),
        "stdout": _capture(result.stdout),
    }
    payload.update(extra)
    return payload


def _parse_rollback(
    result: RunResult, role: str, instance: str, fleet_id: str
) -> dict[str, Any]:
    if len(result.stdout) > MAX_CAPTURE_BYTES:
        raise DeploymentRefused(f"rollback response is oversized for {role}")
    raw = strict_json(result.stdout, f"rollback for {role}")
    required = ROLLBACK_RESPONSE_REQUIRED_KEYS
    allowed = required | ROLLBACK_RESPONSE_OPTIONAL_KEYS
    if not isinstance(raw, dict):
        raise DeploymentRefused(f"rollback response schema is invalid for {role}")
    observed = set(raw)
    if not required.issubset(observed) or not observed.issubset(allowed):
        raise DeploymentRefused(f"rollback response schema is invalid for {role}")
    if (
        raw.get("kind") != KIND_ROLLBACK
        or raw.get("schema_version") != 1
        or raw.get("role") != role
        or raw.get("instance") != instance
        or raw.get("fleet_id") != fleet_id
        or type(raw.get("ok")) is not bool
        or type(raw.get("state_removed")) is not bool
        or not isinstance(raw.get("errors"), list)
        or not isinstance(raw.get("removed_files"), list)
        or not isinstance(raw.get("services_stopped"), list)
        or canonical_bytes(raw) != result.stdout
    ):
        raise DeploymentRefused(f"rollback response identity is invalid for {role}")
    allowed_units = set(ROLLBACK_SERVICES[role])
    stopped = raw["services_stopped"]
    if any(
        not isinstance(item, str) or not UNIT_RE.fullmatch(item) or item not in allowed_units
        for item in stopped
    ) or len(stopped) != len(set(stopped)):
        raise DeploymentRefused(f"rollback stopped a unit outside the exact role allowlist for {role}")
    allowed_removed = (
        set(ROLLBACK_RESIDUALS[role]["binaries"])
        | set(ROLLBACK_RESIDUALS[role]["config"])
        | {f"/etc/systemd/system/{unit}" for unit in ROLLBACK_RESIDUALS[role]["units"]}
        | {f"/etc/systemd/system/{timer}" for timer in ROLLBACK_RESIDUALS[role]["timers"]}
    )
    removed = raw["removed_files"]
    if any(
        not isinstance(item, str)
        or (item not in allowed_removed and ROLLBACK_STAGED_FILE_RE.fullmatch(item) is None)
        for item in removed
    ) or len(removed) != len(set(removed)):
        raise DeploymentRefused(
            f"rollback removed-file list is outside the exact role allowlist for {role}"
        )
    verdict = evaluate_rollback_postconditions(raw)
    if verdict.get("reason") not in {"", "rollback residuals remain"}:
        raise DeploymentRefused(
            f"rollback residual evidence is invalid for {role}: {verdict.get('reason')}"
        )
    if raw["ok"] is True and verdict.get("ok") is not True:
        raise DeploymentRefused(
            f"rollback claimed success while residuals remain for {role}"
        )
    return dict(raw)


def _rollback_remote_role(
    context: Context,
    runner: Runner,
    role: str,
    token: str,
) -> dict[str, Any]:
    instance = context.instances[role]
    paths = _staged_remote_paths(token)
    remote = [
        "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", REMOTE_ROLLBACK_BOOTSTRAP,
        token, role, instance["name"], context.fleet_id,
        paths["bundle"], paths["helper"], paths["manifest"], paths["sidecar"],
        REMOTE_STATE,
    ]
    result = runner.run(_fixed_ssh(context, role, remote), timeout_seconds=120)
    if SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
        return {
            "ok": False,
            "error": "rollback returned credential-shaped output",
            "exit_code": result.exit_code,
            "instance": instance["name"],
            "role": role,
        }
    try:
        raw = _parse_rollback(result, role, instance["name"], context.fleet_id)
    except DeploymentRefused as exc:
        return {
            "ok": False,
            "error": str(exc),
            "exit_code": result.exit_code,
            "instance": instance["name"],
            "role": role,
            "stderr": _capture(result.stderr),
            "stdout": _capture(result.stdout),
        }
    raw["exit_code"] = result.exit_code
    if result.exit_code != 0 or raw.get("ok") is not True:
        raw["ok"] = False
    if "residuals" in raw:
        verdict = evaluate_rollback_postconditions(raw)
        if verdict.get("ok") is not True:
            raw["ok"] = False
            raw["error"] = str(verdict.get("reason") or "rollback residuals remain")
    return raw


def evaluate_rollback_postconditions(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed unless every local residual class was inspected and is empty."""
    role = raw.get("role")
    if role not in ROLLBACK_RESIDUALS:
        return {"ok": False, "present": [], "reason": "rollback residual role is invalid"}
    inspected = raw.get("inspected")
    residuals = raw.get("residuals")
    if inspected != list(ROLLBACK_RESIDUAL_CLASSES):
        return {
            "ok": False,
            "present": [],
            "reason": "rollback residual inspection is incomplete",
        }
    if not isinstance(residuals, dict) or set(residuals) != set(ROLLBACK_RESIDUAL_CLASSES):
        return {
            "ok": False,
            "present": [],
            "reason": "rollback residual evidence schema is invalid",
        }
    present: list[str] = []
    for cls in ROLLBACK_RESIDUAL_CLASSES:
        items = residuals[cls]
        allowed = set(ROLLBACK_RESIDUALS[role][cls])
        if not isinstance(items, list):
            return {
                "ok": False,
                "present": [],
                "reason": "rollback residual names are invalid",
            }
        if any(not isinstance(item, str) for item in items) or len(items) != len(set(items)):
            return {
                "ok": False,
                "present": [],
                "reason": "rollback residual names are invalid",
            }
        for item in items:
            if not isinstance(item, str) or not item or item not in allowed:
                return {
                    "ok": False,
                    "present": [],
                    "reason": "rollback residual name is outside the exact role allowlist",
                }
            present.append(f"{cls}:{item}")
    if present:
        return {
            "ok": False,
            "present": present,
            "reason": "rollback residuals remain",
        }
    return {"ok": True, "present": [], "reason": ""}


def _flatten_residuals(key: str) -> list[str]:
    values: set[str] = set()
    for role in ROLES:
        values.update(ROLLBACK_RESIDUALS[role][key])
    return sorted(values)


def inventory_cleanup_targets(
    context: Context, identities: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Exact cleanup inventory from the authenticated fleet. No cloud action."""
    names = _proof_resource_names(context.fleet_id, context.instances)
    instance_identities = (
        identities.get("instances") if isinstance(identities, Mapping) else None
    )
    instances: list[dict[str, Any]] = []
    for role in ROLES:
        item: dict[str, Any] = {
            "name": context.instances[role]["name"],
            "role": role,
            "zone": context.instances[role]["zone"],
        }
        if isinstance(instance_identities, dict) and isinstance(
            instance_identities.get(role), dict
        ):
            expected = instance_identities[role]
            if "creation_transaction" in expected:
                item["creation_transaction"] = copy.deepcopy(
                    expected["creation_transaction"]
                )
        instances.append(item)
    return {
        "binaries": _flatten_residuals("binaries"),
        "config": _flatten_residuals("config"),
        "firewall_nat": _flatten_residuals("firewall_nat"),
        "firewalls": list(names["firewalls"]),
        "instances": instances,
        "network": names["network"],
        "project": context.project,
        "subnets": list(names["subnets"]),
        "timers": _flatten_residuals("timers"),
        "units": _flatten_residuals("units"),
        "users": _flatten_residuals("users"),
    }


def plan_cleanup_execution(
    context: Context,
    identities: Mapping[str, Any],
    *,
    authorized: bool,
) -> dict[str, Any]:
    """Emit the exact cleanup plan. Unauthorized plans contain no mutations."""
    targets = inventory_cleanup_targets(context, identities)
    if authorized is not True:
        return {
            "authorized": False,
            "reason": "cleanup not authorized",
            "steps": [],
            "targets": targets,
        }
    if not _preflight_complete(context, identities):
        return {
            "authorized": True,
            "reason": "proof resource identity was not established for every role",
            "steps": [],
            "targets": targets,
        }
    names = _proof_resource_names(context.fleet_id, context.instances)
    steps: list[dict[str, Any]] = []
    for role in ROLES:
        inst = context.instances[role]
        steps.extend(
            [
                {
                    "action": "describe-instance",
                    "name": inst["name"],
                    "role": role,
                    "zone": inst["zone"],
                },
                {
                    "action": "disable-deletion-protection",
                    "name": inst["name"],
                    "role": role,
                    "zone": inst["zone"],
                },
                {
                    "action": "delete-instance",
                    "name": inst["name"],
                    "role": role,
                    "zone": inst["zone"],
                },
                {
                    "action": "prove-absence-instance",
                    "name": inst["name"],
                    "role": role,
                    "zone": inst["zone"],
                },
            ]
        )
    for firewall in names["firewalls"]:
        steps.extend(
            [
                {"action": "describe-firewall", "name": firewall, "type": "firewall"},
                {"action": "delete-firewall", "name": firewall, "type": "firewall"},
                {
                    "action": "prove-absence-firewall",
                    "name": firewall,
                    "type": "firewall",
                },
            ]
        )
    for subnet in names["subnets"]:
        steps.extend(
            [
                {
                    "action": "describe-subnet",
                    "name": subnet["name"],
                    "region": subnet["region"],
                    "type": "subnet",
                },
                {
                    "action": "delete-subnet",
                    "name": subnet["name"],
                    "region": subnet["region"],
                    "type": "subnet",
                },
                {
                    "action": "prove-absence-subnet",
                    "name": subnet["name"],
                    "region": subnet["region"],
                    "type": "subnet",
                },
            ]
        )
    network = names["network"]
    steps.extend(
        [
            {"action": "describe-network", "name": network, "type": "network"},
            {"action": "delete-network", "name": network, "type": "network"},
            {"action": "prove-absence-network", "name": network, "type": "network"},
        ]
    )
    for step in steps:
        action = step["action"]
        if (
            action.startswith("delete-") or action == "disable-deletion-protection"
        ) and action not in CLEANUP_PLAN_MUTATIONS:
            raise DeploymentRefused("cleanup plan mutation is not in the fail-closed allowlist")
    return {
        "authorized": True,
        "reason": "",
        "steps": steps,
        "targets": targets,
    }


def _quoted_compute_not_found(identifier: bytes) -> bytes:
    return rb"The resource '(" + identifier + rb")' was not found"


def _compute_describe_not_found_re(name: str) -> re.Pattern[bytes]:
    quoted = re.escape(name.encode("ascii"))
    segment = rb"[^'\r\n/]+"
    bare = _quoted_compute_not_found(quoted)
    typed = _quoted_compute_not_found(
        rb"projects/" + segment + rb"/"
        rb"(?:zones/" + segment + rb"/instances|"
        rb"regions/" + segment + rb"/subnetworks|"
        rb"global/(?:networks|firewalls))/"
        + quoted
    )

    def envelope(command: bytes, path: bytes) -> bytes:
        resource = rb"(?:" + path + quoted + rb"|" + quoted + rb")"
        return (
            rb"\(gcloud\.compute\." + command + rb"\) Could not fetch resource:\r?\n"
            rb" - " + _quoted_compute_not_found(resource)
        )

    body = rb"|".join(
        (
            bare,
            typed,
            envelope(
                rb"instances\.describe",
                rb"projects/" + segment + rb"/zones/" + segment + rb"/instances/",
            ),
            envelope(
                rb"firewall-rules\.describe",
                rb"projects/" + segment + rb"/global/firewalls/",
            ),
            envelope(
                rb"networks\.describe",
                rb"projects/" + segment + rb"/global/networks/",
            ),
            envelope(
                rb"networks\.subnets\.describe",
                rb"projects/" + segment + rb"/regions/" + segment + rb"/subnetworks/",
            ),
        )
    )
    return re.compile(rb"(?:ERROR: )?(?:" + body + rb")")


def _parse_compute_describe_not_found(
    combined: bytes, name: str
) -> re.Match[bytes] | None:
    document = combined.strip()
    if not document:
        return None
    return _compute_describe_not_found_re(name).fullmatch(document)


def _absence_wrapper_envelope(parsed: re.Match[bytes]) -> bytes | None:
    captured = [
        parsed.span(index)
        for index, value in enumerate(parsed.groups(), start=1)
        if value is not None
    ]
    if len(captured) != 1:
        return None
    start, end = captured[0]
    if start < 0 or end < start:
        return None
    return parsed.string[:start] + parsed.string[end:]


def _exact_provider_resource_not_found(combined: bytes, name: str) -> bool:
    """Accept only a complete Compute describe not-found document.

    The entire stdout/stderr document must fullmatch a genuine Compute 404:
    the bare `The resource '<name>' was not found` sentence, that sentence
    with a Compute instance/subnetwork/network/firewall path, or either form
    wrapped in the exact `gcloud compute ... describe` envelope. Auth, IAM,
    API-disabled, gRPC, credentials/reauth, and non-Compute product text in
    the envelope is never absence proof, even when the document embeds that
    exact Compute sentence or a generic NOT_FOUND token. Hyphen tokens such
    as iam, oauth, grpc, preauth, or reauth inside the validated quoted
    resource name or path are identifiers, not wrapper text.
    """
    parsed = _parse_compute_describe_not_found(combined, name)
    if parsed is None:
        return False
    envelope = _absence_wrapper_envelope(parsed)
    if envelope is None:
        return False
    if AUTH_OR_SERVICE_ACCOUNT_RE.search(envelope):
        return False
    if NON_COMPUTE_PRODUCT_ENVELOPE_RE.search(envelope):
        return False
    return True


def _describe_absence_state(result: RunResult, name: str) -> str:
    name_bytes = name.encode("ascii")
    combined = result.stderr + b"\n" + result.stdout
    parsed: Any = None
    if result.stdout.strip():
        try:
            parsed = _strict_json_utf8(result.stdout, "post-delete describe")
        except DeploymentRefused:
            parsed = None
    if isinstance(parsed, dict) and parsed.get("name") == name:
        return "present"
    if result.exit_code == 0:
        return "inconclusive"
    if (
        result.exit_code != 0
        and name_bytes in combined
        and _exact_provider_resource_not_found(combined, name)
        and not (isinstance(parsed, dict) and parsed.get("name") == name)
    ):
        return "absent"
    return "inconclusive"


def _prove_named_absence(
    runner: Runner,
    argv: Sequence[str],
    *,
    name: str,
    label: str,
) -> dict[str, Any]:
    _forbid_selection(argv, label)
    result = runner.run(list(argv), timeout_seconds=60)
    payload: dict[str, Any] = {
        "action": "prove-absence",
        "command": " ".join(argv[:5]),
        "exit_code": result.exit_code,
        "name": name,
        "stderr": _capture(result.stderr),
        "stdout": _capture(result.stdout),
    }
    if SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
        payload["ok"] = False
        payload["error"] = f"{label} returned credential-shaped output"
        return payload
    state = _describe_absence_state(result, name)
    payload["ok"] = state == "absent"
    if state == "present":
        payload["error"] = f"post-delete presence of {label}"
    elif state != "absent":
        payload["error"] = f"post-delete absence of {label} was not proven"
    return payload


def execute_cleanup_plan(
    context: Context,
    runner: Runner,
    identities: Mapping[str, Any],
    *,
    authorized: bool,
) -> dict[str, Any]:
    """Execute only the planned proof-resource deletes after explicit authorization."""
    plan = plan_cleanup_execution(context, identities, authorized=authorized)
    if authorized is not True:
        return {
            "reason": plan["reason"],
            "results": [],
            "status": "skipped",
            "targets": plan["targets"],
        }
    if not plan["steps"]:
        return {
            "reason": plan["reason"] or "cleanup plan contained no authorized steps",
            "results": [],
            "status": "skipped",
            "targets": plan["targets"],
        }
    names = _proof_resource_names(context.fleet_id, context.instances)
    results: list[dict[str, Any]] = []
    failed = False
    apply_created = _parse_gce_timestamp(context.apply["created_utc"], "apply creation time")
    now = datetime.now(timezone.utc)
    instance_identities = identities["instances"]

    def mark_failed(payload: Mapping[str, Any]) -> dict[str, Any]:
        nonlocal failed
        failed = True
        return dict(payload)

    for role in ROLES:
        expected = instance_identities[role]
        try:
            live = _describe_and_prove(
                context, runner, role, now=now, apply_created=apply_created
            )
            if not _same_creation_identity(live, expected):
                raise DeploymentRefused(
                    f"cleanup target identity does not match the proven creation transaction for {role}"
                )
        except DeploymentRefused as exc:
            results.append(
                mark_failed(
                    {
                        "action": "describe",
                        "ok": False,
                        "role": role,
                        "instance": expected["name"],
                        "error": str(exc),
                        "creation_transaction": copy.deepcopy(
                            expected["creation_transaction"]
                        ),
                    }
                )
            )
            continue
        update = runner.run(_fixed_update_no_protection(context, role), timeout_seconds=120)
        results.append(
            _command_result(
                "gcloud compute instances update",
                update,
                action="disable-deletion-protection",
                role=role,
                instance=expected["name"],
                creation_transaction=copy.deepcopy(expected["creation_transaction"]),
            )
        )
        if update.exit_code != 0:
            failed = True
            continue
        delete = runner.run(_fixed_delete_instance(context, role), timeout_seconds=180)
        results.append(
            _command_result(
                "gcloud compute instances delete",
                delete,
                action="delete-instance",
                role=role,
                instance=expected["name"],
                creation_transaction=copy.deepcopy(expected["creation_transaction"]),
            )
        )
        if delete.exit_code != 0:
            failed = True
        absence = _prove_named_absence(
            runner,
            _fixed_describe(context, role),
            name=expected["name"],
            label=f"instance {expected['name']}",
        )
        absence["role"] = role
        absence["type"] = "instance"
        absence["instance"] = expected["name"]
        absence["creation_transaction"] = copy.deepcopy(expected["creation_transaction"])
        results.append(absence if absence.get("ok") is True else mark_failed(absence))

    def refuse_stale(label: str, expected: Mapping[str, Any], live: Mapping[str, Any]) -> None:
        if not _same_resource_identity(live, expected):
            raise DeploymentRefused(
                f"cleanup target identity does not match the proven {label} "
                "project, name, type, creation transaction, labels, or fingerprint"
            )

    for firewall in names["firewalls"]:
        expected = identities["firewalls"][firewall]
        try:
            live = _describe_and_prove_firewall(
                context,
                runner,
                firewall,
                now=now,
                apply_created=apply_created,
                expected_network=names["network"],
            )
            refuse_stale("firewall", expected, live)
        except DeploymentRefused as exc:
            results.append(
                mark_failed(
                    {
                        "action": "describe",
                        "ok": False,
                        "name": firewall,
                        "type": "firewall",
                        "error": str(exc),
                        "creation_transaction": copy.deepcopy(
                            expected["creation_transaction"]
                        ),
                        "fingerprint": expected["fingerprint"],
                        "label_fingerprint": expected["label_fingerprint"],
                    }
                )
            )
            continue
        result = runner.run(_fixed_delete_firewall(context, firewall), timeout_seconds=120)
        results.append(
            _command_result(
                "gcloud compute firewall-rules delete",
                result,
                action="delete-firewall",
                name=firewall,
                type="firewall",
                creation_transaction=copy.deepcopy(expected["creation_transaction"]),
                fingerprint=expected["fingerprint"],
                label_fingerprint=expected["label_fingerprint"],
            )
        )
        if result.exit_code != 0:
            failed = True
        absence = _prove_named_absence(
            runner,
            _fixed_describe_firewall(context, firewall),
            name=firewall,
            label=f"firewall {firewall}",
        )
        absence["type"] = "firewall"
        absence["fingerprint"] = expected["fingerprint"]
        absence["label_fingerprint"] = expected["label_fingerprint"]
        absence["creation_transaction"] = copy.deepcopy(expected["creation_transaction"])
        results.append(absence if absence.get("ok") is True else mark_failed(absence))
    for subnet in names["subnets"]:
        expected = identities["subnets"][subnet["name"]]
        try:
            live = _describe_and_prove_subnet(
                context,
                runner,
                subnet["name"],
                subnet["region"],
                now=now,
                apply_created=apply_created,
                expected_network=names["network"],
            )
            refuse_stale("subnet", expected, live)
        except DeploymentRefused as exc:
            results.append(
                mark_failed(
                    {
                        "action": "describe",
                        "ok": False,
                        "name": subnet["name"],
                        "region": subnet["region"],
                        "type": "subnet",
                        "error": str(exc),
                        "creation_transaction": copy.deepcopy(
                            expected["creation_transaction"]
                        ),
                        "fingerprint": expected["fingerprint"],
                        "label_fingerprint": expected["label_fingerprint"],
                    }
                )
            )
            continue
        result = runner.run(
            _fixed_delete_subnet(context, subnet["name"], subnet["region"]),
            timeout_seconds=120,
        )
        results.append(
            _command_result(
                "gcloud compute networks subnets delete",
                result,
                action="delete-subnet",
                name=subnet["name"],
                region=subnet["region"],
                type="subnet",
                creation_transaction=copy.deepcopy(expected["creation_transaction"]),
                fingerprint=expected["fingerprint"],
                label_fingerprint=expected["label_fingerprint"],
            )
        )
        if result.exit_code != 0:
            failed = True
        absence = _prove_named_absence(
            runner,
            _fixed_describe_subnet(context, subnet["name"], subnet["region"]),
            name=subnet["name"],
            label=f"subnet {subnet['name']}",
        )
        absence["type"] = "subnet"
        absence["region"] = subnet["region"]
        absence["fingerprint"] = expected["fingerprint"]
        absence["label_fingerprint"] = expected["label_fingerprint"]
        absence["creation_transaction"] = copy.deepcopy(expected["creation_transaction"])
        results.append(absence if absence.get("ok") is True else mark_failed(absence))
    expected_network = identities["network"]
    try:
        live = _describe_and_prove_network(
            context,
            runner,
            names["network"],
            now=now,
            apply_created=apply_created,
        )
        refuse_stale("network", expected_network, live)
        network_ready = True
        network_error = None
    except DeploymentRefused as exc:
        network_ready = False
        network_error = exc
    if not network_ready:
        results.append(
            mark_failed(
                {
                    "action": "describe",
                    "ok": False,
                    "name": names["network"],
                    "type": "network",
                    "error": str(network_error),
                    "creation_transaction": copy.deepcopy(
                        expected_network["creation_transaction"]
                    ),
                    "fingerprint": expected_network["fingerprint"],
                    "label_fingerprint": expected_network["label_fingerprint"],
                }
            )
        )
    else:
        result = runner.run(_fixed_delete_network(context, names["network"]), timeout_seconds=120)
        results.append(
            _command_result(
                "gcloud compute networks delete",
                result,
                action="delete-network",
                name=names["network"],
                type="network",
                creation_transaction=copy.deepcopy(expected_network["creation_transaction"]),
                fingerprint=expected_network["fingerprint"],
                label_fingerprint=expected_network["label_fingerprint"],
            )
        )
        if result.exit_code != 0:
            failed = True
        absence = _prove_named_absence(
            runner,
            _fixed_describe_network(context, names["network"]),
            name=names["network"],
            label=f"network {names['network']}",
        )
        absence["type"] = "network"
        absence["fingerprint"] = expected_network["fingerprint"]
        absence["label_fingerprint"] = expected_network["label_fingerprint"]
        absence["creation_transaction"] = copy.deepcopy(
            expected_network["creation_transaction"]
        )
        results.append(absence if absence.get("ok") is True else mark_failed(absence))
    return {
        "reason": "bounded proof-resource cleanup was partial" if failed else "",
        "results": results,
        "status": "failed" if failed else "passed",
        "targets": plan["targets"],
    }


def _cleanup_resources(
    context: Context, runner: Runner, identities: Mapping[str, Any]
) -> dict[str, Any]:
    return execute_cleanup_plan(context, runner, identities, authorized=True)


def _skipped_resources(
    reason: str, targets: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "reason": reason,
        "results": [],
        "status": "skipped",
        "targets": dict(targets) if isinstance(targets, Mapping) else {},
    }


def _normalize_resources(resources: Mapping[str, Any] | None) -> dict[str, Any]:
    raw = dict(resources or {})
    payload = {
        "reason": raw.get("reason") if isinstance(raw.get("reason"), str) else "",
        "results": list(raw["results"]) if isinstance(raw.get("results"), list) else [],
        "status": raw["status"] if isinstance(raw.get("status"), str) else "skipped",
        "targets": dict(raw["targets"]) if isinstance(raw.get("targets"), dict) else {},
    }
    if set(payload) != CLEANUP_RESOURCES_KEYS:
        raise DeploymentRefused("cleanup resource schema is not exact")
    return payload


def _normalize_cleanup(
    cleanup: Mapping[str, Any],
    *,
    authorized: bool,
) -> dict[str, Any]:
    resources = _normalize_resources(
        cleanup.get("resources") if isinstance(cleanup.get("resources"), dict) else None
    )
    remote = cleanup.get("remote")
    payload = {
        "acceptance_receipt_required": False,
        "authorized": authorized is True,
        "remote": dict(remote) if isinstance(remote, dict) else {},
        "resources": resources,
        "status": cleanup["status"] if isinstance(cleanup.get("status"), str) else "skipped",
    }
    if set(payload) != CLEANUP_KEYS:
        raise DeploymentRefused("cleanup schema is not exact")
    return payload


def consume_execution_receipt(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """Prove the exact fleet-consumable schema and return the same mapping.

    This does not add candidate_id, cleanup, preflight, or record_chain_sha256.
    """
    if not isinstance(raw, dict) or set(raw) != EXECUTION_KEYS:
        raise DeploymentRefused("deployment execution receipt schema is not exact")
    if raw["kind"] != KIND_EXECUTION or raw["schema_version"] != EXECUTION_SCHEMA_VERSION:
        raise DeploymentRefused("deployment execution receipt kind/schema is invalid")
    if not isinstance(raw.get("cleanup"), dict) or set(raw["cleanup"]) != CLEANUP_KEYS:
        raise DeploymentRefused("deployment execution cleanup schema is not exact")
    if (
        not isinstance(raw["cleanup"].get("resources"), dict)
        or set(raw["cleanup"]["resources"]) != CLEANUP_RESOURCES_KEYS
    ):
        raise DeploymentRefused("deployment execution cleanup resource schema is not exact")
    if not isinstance(raw.get("preflight"), dict) or set(raw["preflight"]) != PREFLIGHT_KEYS:
        raise DeploymentRefused("deployment execution preflight schema is not exact")
    if raw["cleanup"].get("acceptance_receipt_required") is not False:
        raise DeploymentRefused("deployment execution cleanup must not require an acceptance receipt")
    return raw


def _execution_receipt(
    context: Context,
    *,
    status: str,
    started: str,
    cleanup: Mapping[str, Any],
    preflight: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    markers: Mapping[str, Any],
    bundle_sha: str | None,
    helper_sha: str | None,
    failure: Mapping[str, Any] | None,
    authorized_cleanup: bool,
    runner: Runner,
) -> dict[str, Any]:
    if status in {"passed", "cleaned"} and not gcloud_custody.runner_may_emit_production_pass(runner):
        status = "blocked"
    chain = records[-1]["record_sha256"] if records else ZERO_SHA256
    receipt = {
        "apply_sha256": context.apply_sha256,
        "bundle_sha256": bundle_sha if bundle_sha is not None else ZERO_SHA256,
        "candidate_id": context.manifest["candidate_id"],
        "cleanup": _normalize_cleanup(cleanup, authorized=authorized_cleanup),
        "client_release_binding": context.client_release_binding,
        "deployment_inputs": _deployment_ref(
            context.manifest_path,
            context.manifest_sha256,
            context.manifest_bytes,
            context.manifest["candidate_id"],
        ),
        "deployment_manifest_sha256": context.manifest_sha256,
        "ended_utc": _utc_now(),
        "failure": dict(failure) if failure else {},
        "fleet_id": context.fleet_id,
        "kind": KIND_EXECUTION,
        "markers": dict(markers),
        "plan_sha256": context.plan_sha256,
        "preflight": _preflight_view(preflight),
        "record_chain_sha256": chain,
        "records": list(records),
        "remote_helper_sha256": helper_sha if helper_sha is not None else REMOTE_HELPER_SHA256,
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "started_utc": started,
        "status": status,
    }
    return dict(consume_execution_receipt(receipt))


def _failure_cleanup(
    context: Context,
    runner: Runner,
    identities: Mapping[str, Any],
    contacted_roles: Sequence[str],
    token: str | None,
    *,
    confirm_cleanup: bool,
) -> dict[str, Any]:
    remote: dict[str, Any] = {}
    remote_failed = False
    for role in ROLES:
        if role not in contacted_roles:
            continue
        if token is None:
            remote[role] = {"ok": False, "error": "rollback staged identity is missing"}
            remote_failed = True
            continue
        try:
            payload = _rollback_remote_role(context, runner, role, token)
        except Exception as exc:
            payload = {
                "ok": False,
                "error": str(exc),
                "instance": context.instances[role]["name"],
                "role": role,
            }
        remote[role] = payload
        if payload.get("ok") is not True:
            remote_failed = True
    authorized = confirm_cleanup is True
    targets = inventory_cleanup_targets(context, identities)
    if not authorized:
        resources = _skipped_resources("cleanup not authorized", targets=targets)
        resource_failed = False
    elif not _preflight_complete(context, identities):
        resources = _skipped_resources(
            "proof resource identity was not established for every role",
            targets=targets,
        )
        resource_failed = False
    else:
        try:
            resources = execute_cleanup_plan(
                context, runner, identities, authorized=True
            )
        except Exception as exc:
            resources = {
                "reason": str(exc),
                "results": [],
                "status": "failed",
                "targets": targets,
            }
        resource_failed = resources.get("status") != "passed"
    if not contacted_roles and resources.get("status") == "skipped" and not remote:
        status = "skipped"
    elif remote_failed or resource_failed:
        status = "failed"
    else:
        status = "passed"
    return {
        "acceptance_receipt_required": False,
        "authorized": authorized,
        "remote": remote,
        "resources": resources,
        "status": status,
    }


def load_credential_input(
    *,
    path: Path | None,
    kind: str | None,
    account: str | None,
    project: str | None,
) -> gcloud_custody.GcloudCredentialInput | None:
    values = (path, kind, account, project)
    if all(item is None or item == "" for item in values):
        return None
    if any(item is None or item == "" for item in values):
        raise DeploymentRefused("Google Cloud CLI credential input is incomplete")
    if kind not in {
        gcloud_custody.SERVICE_ACCOUNT_KIND,
        gcloud_custody.WORKLOAD_IDENTITY_KIND,
    }:
        raise DeploymentRefused("Google Cloud CLI credential kind is unsupported")
    return gcloud_custody.GcloudCredentialInput(
        kind=kind,
        path=Path(path),
        expected_account=str(account),
        expected_project=str(project),
    )


def _bind_runner(
    context: Context,
    runner: Runner,
    credential: gcloud_custody.GcloudCredentialInput | None = None,
) -> tuple[Context, Runner]:
    if credential is not None:
        try:
            gcloud_custody.authenticate_credential(credential)
            gcloud_custody.require_bound_project(credential, context.project)
        except gcloud_custody.GcloudCustodyError as suc:
            raise DeploymentRefused(str(suc)) from suc
    runner_type = type(runner)
    if runner_type is SubprocessRunner:
        if credential is None:
            raise DeploymentRefused(gcloud_custody.MISSING_IDENTITY)
        try:
            bound = gcloud_custody.bind_production_runner(
                runner,
                context.gcloud_bin,
                credential,
                pin_manifest=TOOLCHAIN_PINS,
            )
        except gcloud_custody.GcloudCustodyError as suc:
            raise DeploymentRefused(str(suc)) from suc
        context = replace(context, gcloud_bin=str(bound.verified.executable))
        runner = bound
    elif runner_type is gcloud_custody.CustodyRunner:
        try:
            gcloud_custody.require_bound_project(runner.credential, context.project)
        except gcloud_custody.GcloudCustodyError as suc:
            raise DeploymentRefused(str(suc)) from suc
    elif getattr(runner_type, "TEST_ONLY", False) is True:
        pass
    else:
        raise DeploymentRefused(gcloud_custody.ARBITRARY_RUNNER)
    verify_gcloud_version(runner, context.gcloud_bin)
    return context, runner


def _write_new_immutable(path: Path, payload: Mapping[str, Any]) -> None:
    data = canonical_bytes(payload)
    sidecar = path.with_name(path.name + ".sha256")
    if path.exists() or path.is_symlink() or sidecar.exists() or sidecar.is_symlink():
        raise DeploymentRefused("deployment execution output already exists")
    for target, content in ((path, data), (sidecar, f"{sha256_bytes(data)}  {path.name}\n".encode("ascii"))):
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
        try:
            _write_all(fd, content)
            os.fsync(fd)
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)


def _private_output(path: Path, state_parent: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.name != "deployment-execution.json":
        raise DeploymentRefused("output must be absolute and named deployment-execution.json")
    if candidate.parent != state_parent or candidate.exists() or candidate.is_symlink():
        raise DeploymentRefused("output must be new in the authenticated state directory")
    parent = candidate.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700:
        raise DeploymentRefused("state directory must be a real private mode-0700 directory")
    return candidate


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def execute(
    repo_root: Path,
    plan_path: Path,
    apply_path: Path,
    deployment_inputs: Path,
    output: Path,
    *,
    confirm_live_deployment: bool,
    runner: Runner,
    confirm_cleanup: bool = False,
    credential: gcloud_custody.GcloudCredentialInput | None = None,
) -> dict[str, Any]:
    if confirm_live_deployment is not True and confirm_cleanup is not True:
        raise DeploymentRefused("explicit --confirm-live-deployment is required")
    initial = load_context(repo_root, plan_path, apply_path, deployment_inputs)
    initial, runner = _bind_runner(initial, runner, credential=credential)
    destination = _private_output(output, initial.plan_path.parent)
    started = _utc_now()
    apply_created = _parse_gce_timestamp(initial.apply["created_utc"], "apply creation time")

    def finish_failure(
        failure: Mapping[str, Any],
        *,
        identities: Mapping[str, Any],
        contacted: Sequence[str],
        token: str | None,
        bundle_sha: str | None,
        helper_sha: str | None,
        records: Sequence[Mapping[str, Any]],
        extra: Mapping[str, Any] | None = None,
        receipt_status: str = "failed",
    ) -> dict[str, Any]:
        cleanup = _failure_cleanup(
            initial,
            runner,
            identities,
            contacted,
            token,
            confirm_cleanup=confirm_cleanup,
        )
        failure_payload = dict(failure)
        if extra and "failed_step_index" in extra:
            failure_payload["failed_step_index"] = extra["failed_step_index"]
        receipt = _execution_receipt(
            initial,
            status=receipt_status,
            started=started,
            cleanup=cleanup,
            preflight=identities,
            records=records,
            markers={},
            bundle_sha=bundle_sha,
            helper_sha=helper_sha,
            failure=failure_payload,
            authorized_cleanup=confirm_cleanup is True,
            runner=runner,
        )
        _write_new_immutable(destination, receipt)
        return receipt

    if confirm_live_deployment is not True:
        current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
        if current != initial:
            raise DeploymentRefused("authenticated deployment context changed before cleanup")
        try:
            identities = _preflight_identities(
                current,
                runner,
                now=datetime.now(timezone.utc),
                apply_created=apply_created,
            )
            resources = _cleanup_resources(current, runner, identities)
        except DeploymentRefused as exc:
            return finish_failure(
                {"command": "gcloud compute instances describe", "reason": str(exc)},
                identities={},
                contacted=(),
                token=None,
                bundle_sha=None,
                helper_sha=None,
                records=(),
            )
        status = "cleaned" if resources.get("status") == "passed" else "failed"
        receipt = _execution_receipt(
            initial,
            status=status,
            started=started,
            cleanup={
                "acceptance_receipt_required": False,
                "authorized": True,
                "remote": {},
                "resources": resources,
                "status": resources.get("status"),
            },
            preflight=identities,
            records=(),
            markers={},
            bundle_sha=ZERO_SHA256,
            helper_sha=REMOTE_HELPER_SHA256,
            failure=(
                {
                    "command": "proof-resource-cleanup",
                    "reason": "bounded proof-resource cleanup failed",
                }
                if status != "cleaned"
                else {}
            ),
            authorized_cleanup=True,
            runner=runner,
        )
        _write_new_immutable(destination, receipt)
        return receipt

    records: list[dict[str, Any]] = []
    markers: dict[str, Any] = {}
    identities: dict[str, Any] = _empty_preflight()
    contacted: list[str] = []
    token: str | None = None
    bundle_sha: str | None = None
    helper_sha: str | None = None
    previous = ZERO_SHA256
    with tempfile.TemporaryDirectory(prefix="winsvpn-gcp-proof-") as temporary_name:
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o700)
        token = initial.manifest["candidate_id"][:24]
        if not TOKEN_RE.fullmatch(token):
            raise DeploymentRefused("deployment candidate token is invalid")
        current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
        if current != initial:
            raise DeploymentRefused("authenticated deployment context changed before preflight")
        bundle = temporary / f"winsvpn-proof-{token}.tar"
        bundle_sha = build_bundle(initial, bundle)
        helper_data, _ = _read_stable(REMOTE_HELPER, "remote installer helper")
        helper_sha = sha256_bytes(helper_data)
        if helper_sha != REMOTE_HELPER_SHA256:
            raise DeploymentRefused("remote installer helper does not match the reviewed executor pin")
        helper = temporary / f"winsvpn-proof-{token}-remote.py"
        helper.write_bytes(helper_data)
        os.chmod(helper, 0o500)
        manifest_copy = temporary / f"winsvpn-proof-{token}-DEPLOYMENT_INPUTS.json"
        sidecar_copy = temporary / f"winsvpn-proof-{token}-DEPLOYMENT_INPUTS.json.sha256"
        manifest_data, _ = _read_stable(initial.manifest_path, "deployment inputs")
        manifest_sidecar, _ = _read_stable(
            initial.manifest_path.with_name(initial.manifest_path.name + ".sha256"),
            "deployment inputs sidecar",
        )
        del manifest_sidecar
        manifest_copy.write_bytes(manifest_data)
        sidecar_copy.write_bytes(
            f"{initial.manifest_sha256}  {manifest_copy.name}\n".encode("ascii")
        )
        os.chmod(manifest_copy, 0o400)
        os.chmod(sidecar_copy, 0o400)
        staged = {
            "bundle": f"/tmp/{bundle.name}", "bundle_sha256": bundle_sha,
            "helper": f"/tmp/{helper.name}", "helper_sha256": helper_sha,
            "manifest": f"/tmp/{manifest_copy.name}", "sidecar": f"/tmp/{sidecar_copy.name}",
        }
        expected_paths = _staged_remote_paths(token)
        if (
            staged["bundle"] != expected_paths["bundle"]
            or staged["helper"] != expected_paths["helper"]
            or staged["manifest"] != expected_paths["manifest"]
            or staged["sidecar"] != expected_paths["sidecar"]
        ):
            raise DeploymentRefused("staged remote paths escaped the exact candidate identity")
        sources = (bundle, helper, manifest_copy, sidecar_copy)
        try:
            current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
            if current != initial:
                raise DeploymentRefused("authenticated deployment context changed before preflight")
            identities = _preflight_identities(
                current,
                runner,
                now=datetime.now(timezone.utc),
                apply_created=apply_created,
            )
            for role in ROLES:
                current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
                if current != initial:
                    raise DeploymentRefused("authenticated deployment context changed before transfer")
                verify_bundle(current, bundle, bundle_sha)
                verify_remote_helper(helper, helper_sha)
                contacted.append(role)
                transfer = runner.run(
                    _fixed_scp(current, current.instances[role], sources),
                    timeout_seconds=600,
                )
                if transfer.exit_code != 0:
                    return finish_failure(
                        {
                            "command": "gcloud compute scp",
                            "exit_code": transfer.exit_code,
                            "role": role,
                            "stderr": _capture(transfer.stderr),
                            "stdout": _capture(transfer.stdout),
                        },
                        identities=identities,
                        contacted=contacted,
                        token=token,
                        bundle_sha=bundle_sha,
                        helper_sha=helper_sha,
                        records=records,
                    )
            probes: dict[str, dict[str, Any]] = {}
            for role in ROLES:
                current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
                if current != initial:
                    raise DeploymentRefused(
                        "authenticated deployment context changed before runtime probe"
                    )
                verify_bundle(current, bundle, bundle_sha)
                verify_remote_helper(helper, helper_sha)
                probe_result = runner.run(
                    _fixed_ssh(current, role, _runtime_probe_args(role)),
                    timeout_seconds=120,
                )
                probes[role] = _parse_runtime_probe(probe_result, role)
            skipped_steps, previous = _skipped_step_state(probes, current)
            exchange_machine = _exchange_machine_from_probes(probes, identities)
            for installer in initial.installers:
                if installer["index"] in skipped_steps:
                    continue
                current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
                if current != initial:
                    raise DeploymentRefused(
                        "authenticated deployment context changed before an installer step"
                    )
                verify_bundle(current, bundle, bundle_sha)
                verify_remote_helper(helper, helper_sha)
                role = installer["role"]
                remote = _remote_base_args(current, staged, role, previous) + [
                    "--action", "step", "--step-index", str(installer["index"]),
                    "--script", installer["script"],
                    "--script-sha256", installer["script_ref"]["sha256"],
                    "--script-bytes", str(installer["script_ref"]["bytes"]),
                    "--script-mode", str(installer["script_ref"]["mode"]),
                    f"--flag={installer['flag']}",
                ]
                if installer["index"] == LAST_ROLE_STEP[role]:
                    remote.append("--final-role-step")
                result = runner.run(_fixed_ssh(current, role, remote), timeout_seconds=3900)
                response = _parse_remote(result, f"deployment step {installer['index']}")
                record_raw = response.get("record")
                if record_raw is None:
                    raise DeploymentRefused("remote deployment step omitted its audit record")
                record = _validate_record(record_raw, installer, current, previous)
                records.append(record)
                previous = record["record_sha256"]
                if (
                    (result.exit_code == 0) is not (record["exit_code"] == 0)
                    or response.get("ok") is not (record["exit_code"] == 0)
                ):
                    raise DeploymentRefused("gcloud and remote deployment status disagree")
                if record["exit_code"] != 0:
                    return finish_failure(
                        {
                            "command": "remote installer",
                            "failed_step_index": installer["index"],
                            "role": role,
                        },
                        identities=identities,
                        contacted=contacted,
                        token=token,
                        bundle_sha=bundle_sha,
                        helper_sha=helper_sha,
                        records=records,
                        extra={
                            "failed_step_index": installer["index"],
                        },
                    )
            current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
            if current != initial:
                raise DeploymentRefused(
                    "authenticated deployment context changed before control/data exchange"
                )
            verify_bundle(current, bundle, bundle_sha)
            verify_remote_helper(helper, helper_sha)
            _run_control_data_exchange(
                current, runner, staged, previous, exchange_machine
            )
            for role in ROLES:
                current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
                if current != initial:
                    raise DeploymentRefused(
                        "authenticated deployment context changed before marker finalization"
                    )
                verify_bundle(current, bundle, bundle_sha)
                verify_remote_helper(helper, helper_sha)
                remote = _remote_base_args(current, staged, role, previous) + [
                    "--action", "finalize",
                    "--fleet-completed-step-indices",
                    json.dumps(list(range(len(EXPECTED_STEPS))), separators=(",", ":")),
                ]
                result = runner.run(_fixed_ssh(current, role, remote), timeout_seconds=300)
                response = _parse_remote(result, f"marker finalization for {role}")
                marker = response.get("marker")
                if result.exit_code != 0 or response.get("ok") is not True:
                    raise DeploymentRefused(f"marker finalization failed for {role}")
                markers[role] = _validate_final_marker(marker, current, role, previous)
            current = load_context(repo_root, plan_path, apply_path, deployment_inputs)
            if current != initial:
                raise DeploymentRefused(
                    "authenticated deployment context changed before control observation"
                )
            verify_bundle(current, bundle, bundle_sha)
            verify_remote_helper(helper, helper_sha)
            observation_spec = _control_deployment_observation_spec(current)
            observation_result = runner.run(
                _fixed_ssh(
                    current,
                    "control",
                    [
                        "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3",
                        "-I", "-c", REMOTE_DEPLOYMENT_OBSERVATION_BOOTSTRAP,
                        json.dumps(
                            observation_spec,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ],
                ),
                timeout_seconds=120,
            )
            _parse_control_deployment_observation(
                observation_result, observation_spec
            )
        except DeploymentBlocked as exc:
            return finish_failure(
                {"command": "authenticated-deployment", "reason": str(exc)},
                identities=identities,
                contacted=contacted,
                token=token,
                bundle_sha=bundle_sha,
                helper_sha=helper_sha,
                records=records,
                extra=None,
                receipt_status="blocked",
            )
        except DeploymentRefused as exc:
            return finish_failure(
                {"command": "authenticated-deployment", "reason": str(exc)},
                identities=identities,
                contacted=contacted,
                token=token,
                bundle_sha=bundle_sha,
                helper_sha=helper_sha,
                records=records,
                extra=None,
            )
    receipt = _execution_receipt(
        initial,
        status="passed",
        started=started,
        cleanup={
            "acceptance_receipt_required": False,
            "authorized": confirm_cleanup is True,
            "remote": {},
            "resources": {
                "reason": "cleanup not required after passed deployment",
                "results": [],
                "status": "not_required",
                "targets": {},
            },
            "status": "not_required",
        },
        preflight=identities,
        records=records,
        markers=markers,
        bundle_sha=bundle_sha,
        helper_sha=helper_sha,
        failure={},
        authorized_cleanup=confirm_cleanup is True,
        runner=runner,
    )
    _write_new_immutable(destination, receipt)
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repo-root", type=Path, required=True)
    result.add_argument("--plan", type=Path, required=True)
    result.add_argument("--apply", type=Path, required=True)
    result.add_argument("--deployment-inputs", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--confirm-live-deployment", action="store_true")
    result.add_argument("--confirm-cleanup", action="store_true")
    result.add_argument("--credential-path", type=Path)
    result.add_argument("--credential-kind")
    result.add_argument("--credential-account")
    result.add_argument("--credential-project")
    return result


def main(argv: Sequence[str] | None = None, *, runner: Runner | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        credential = load_credential_input(
            path=args.credential_path,
            kind=args.credential_kind,
            account=args.credential_account,
            project=args.credential_project,
        )
        receipt = execute(
            args.repo_root, args.plan, args.apply, args.deployment_inputs, args.output,
            confirm_live_deployment=args.confirm_live_deployment,
            confirm_cleanup=args.confirm_cleanup,
            runner=runner or SubprocessRunner(),
            credential=credential,
        )
    except DeploymentRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(f"{receipt['status'].upper()} deployment execution receipt: {args.output}")
    if receipt["status"] in {"passed", "cleaned"}:
        if receipt.get("cleanup", {}).get("status") == "failed":
            return 1
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
