#!/usr/bin/env python3
"""Collect secret-safe evidence for owner/external deployment inputs.

This tool is intentionally not an authorization tool.  It turns explicit local
bindings into stable file or directory metadata and hashes.  It never copies or
prints input contents, never emits VERIFIED, and never authorizes deployment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


CONTRACT = "winsvpn-production-deployment-owner-inputs-v1"
BINDINGS_CONTRACT = "winsvpn-production-deployment-owner-input-bindings-v1"
SCHEMA_VERSION = 1
SCOPE = "production-server-deployment-only"
PENDING = "PENDING-OWNER-INPUT"
PRESENT = "PRESENT-UNVERIFIED"
CONFLICT = "CONFLICT"
VERIFIED = "VERIFIED"
HEX64_PATTERN = r"^[0-9a-f]{64}$"
GIT_OID_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
SAFE_ID_PATTERN = r"^[a-z0-9][a-z0-9.-]{0,95}$"
HEX64_RE = re.compile(HEX64_PATTERN)
GIT_OID_RE = re.compile(GIT_OID_PATTERN)
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
SAFE_ID_RE = re.compile(SAFE_ID_PATTERN)
REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "tools/deployment_owner_inputs.schema.json"
TEMPLATE_PATH = REPO_ROOT / "deploy/production-input-evidence/PENDING-OWNER-INPUT.json"
COLLECTOR_PATH = REPO_ROOT / "tools/deployment_owner_inputs.py"
OUTPUT_NAME = "deployment-owner-input-evidence.json"
OUTPUT_DIGEST_NAME = OUTPUT_NAME + ".sha256"

TOP_LEVEL_KEYS = {
    "schema_version",
    "contract",
    "scope",
    "created_at_utc",
    "status",
    "deployment_authorized",
    "secret_material_redacted",
    "approved_sha",
    "source_documents",
    "producer",
    "authorization",
    "scope_exclusions",
    "workstation_observations",
    "items",
}
ITEM_KEYS = {
    "id",
    "stage",
    "roles",
    "category",
    "supplier_kind",
    "sensitivity",
    "artifact_kind",
    "required",
    "owner_only",
    "status",
    "source_refs",
    "requirement",
    "required_evidence",
    "candidate_paths",
    "depends_on",
    "evidence",
    "missing_reason",
    "required_action",
}
IMMUTABLE_ITEM_KEYS = ITEM_KEYS - {"status", "evidence", "missing_reason", "required_action"}
SOURCE_DOCUMENT_KEYS = {"path", "sha256", "purpose"}
SOURCE_REF_KEYS = {"path", "line_start", "line_end"}
PRODUCER_KEYS = {
    "collector_path",
    "collector_sha256",
    "schema_path",
    "schema_sha256",
    "template_path",
    "template_sha256",
    "collector_closure_sha256",
    "repository_head",
    "repository_clean",
}
AUTHORIZATION_KEYS = {
    "method",
    "approved_sha",
    "attestation_path",
    "attestation_sha256",
    "signer",
    "signed_at_utc",
}
EXCLUSION_KEYS = {"id", "reason", "source_refs"}
OBSERVATION_KEYS = {
    "id",
    "relates_to",
    "path",
    "result",
    "kind",
    "mode",
    "size_bytes",
    "sha256",
    "captured_at_utc",
    "note",
}
EVIDENCE_KEYS = {
    "path",
    "kind",
    "sha256",
    "size_bytes",
    "mode",
    "uid",
    "gid",
    "captured_at_utc",
    "member_count",
}
BINDINGS_TOP_KEYS = {"schema_version", "contract", "claimed_approved_sha", "items"}
BINDING_KEYS = {"id", "path", "expected_sha256"}
TOP_STATUSES = {PENDING, PRESENT, CONFLICT, VERIFIED}
ITEM_STATUSES = {PENDING, PRESENT, CONFLICT, VERIFIED}
STAGES = {"stage-0", "stage-1", "stage-2", "stage-3", "bridge-exit"}
STAGE_RANK = {"stage-0": 0, "stage-1": 1, "stage-2": 2, "stage-3": 3, "bridge-exit": 4}
ROLES = {"shared", "hub", "spain", "germany", "aicore", "bridge"}
CATEGORIES = {
    "audit-authority", "role-input", "host-trust", "recovery", "network-identity",
    "artifact-authority", "key-custody", "external-service", "disk-custody",
    "physical-site", "bridge-governance", "external-test", "lane-authority",
}
SUPPLIER_KINDS = {
    "owner", "provider-console", "final-auditor", "authorized-producer",
    "external-tester", "preceding-lane",
}
SENSITIVITIES = {"public", "metadata-sensitive", "secret"}
ARTIFACT_KINDS = {"file", "directory", "binary", "report", "attestation"}
OBSERVATION_RESULTS = {"LOCATED-UNVERIFIED", "ABSENT"}
EVIDENCE_KINDS = {"file", "directory"}

# A schema keyword outside this closed set is an error.  This prevents a future
# edit from adding a constraint that this standard-library validator silently
# ignores.
SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "const",
    "enum",
    "pattern",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
}


class EvidenceError(RuntimeError):
    """A fail-closed evidence validation or collection error."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strict_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key: {!r}".format(key))
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EvidenceError("non-finite JSON number is forbidden: {}".format(value))


def strict_json_load(path: Path, label: str, secure: bool = False) -> Any:
    if secure:
        data, _ = _read_stable_file(path, owner_only=True)
    else:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise EvidenceError("cannot read {}: {}".format(label, exc)) from exc
    return strict_json_load_bytes(data, label)


def strict_json_load_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_nonfinite,
        )
    except UnicodeDecodeError as exc:
        raise EvidenceError("{} is not UTF-8 JSON".format(label)) from exc
    except json.JSONDecodeError as exc:
        raise EvidenceError("{} is invalid JSON: {}".format(label, exc)) from exc


def _require_exact_keys(value: Any, expected: set, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError("{} must be an object".format(label))
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EvidenceError("{} keys mismatch; missing={} extra={}".format(label, missing, extra))
    return value


def _require_string(value: Any, label: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise EvidenceError("{} must be a{} string".format(label, " non-empty" if not allow_empty else ""))
    return value


def _require_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise EvidenceError("{} must be a boolean".format(label))
    return value


def _require_int(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError("{} must be an integer >= {}".format(label, minimum))
    return value


def _require_sha(value: Any, label: str, nullable: bool = False) -> Optional[str]:
    if nullable and value is None:
        return None
    text = _require_string(value, label)
    if not HEX64_RE.fullmatch(text):
        raise EvidenceError("{} must be a lowercase SHA-256".format(label))
    return text


def _require_git_oid(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not GIT_OID_RE.fullmatch(text):
        raise EvidenceError("{} must be a full lowercase Git object ID".format(label))
    return text


def _require_utc(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not UTC_RE.fullmatch(text):
        raise EvidenceError("{} must use YYYY-MM-DDTHH:MM:SSZ".format(label))
    return text


def _require_string_list(value: Any, label: str, nonempty: bool = True) -> List[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise EvidenceError("{} must be a{} array".format(label, " non-empty" if nonempty else ""))
    result = []
    for index, entry in enumerate(value):
        result.append(_require_string(entry, "{}[{}]".format(label, index)))
    if len(set(result)) != len(result):
        raise EvidenceError("{} contains duplicates".format(label))
    return result


def _walk_schema(node: Any, label: str, definitions: Mapping[str, Any]) -> None:
    if not isinstance(node, dict):
        raise EvidenceError("{} must be a schema object".format(label))
    unknown = set(node) - SUPPORTED_SCHEMA_KEYWORDS
    if unknown:
        raise EvidenceError("{} uses unsupported schema keywords: {}".format(label, sorted(unknown)))
    reference = node.get("$ref")
    if reference is not None:
        reference = _require_string(reference, label + ".$ref")
        prefix = "#/$defs/"
        if not reference.startswith(prefix) or reference[len(prefix):] not in definitions:
            raise EvidenceError("{} has an unsupported or unresolved $ref".format(label))
    properties = node.get("properties", {})
    if not isinstance(properties, dict):
        raise EvidenceError("{}.properties must be an object".format(label))
    for name, child in properties.items():
        _walk_schema(child, "{}.properties.{}".format(label, name), definitions)
    child = node.get("items")
    if child is not None:
        _walk_schema(child, label + ".items", definitions)


def validate_schema_contract(schema: Any) -> None:
    if not isinstance(schema, dict):
        raise EvidenceError("schema must be an object")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise EvidenceError("schema.$defs must be an object")
    _walk_schema(schema, "schema", definitions)
    for name, child in definitions.items():
        _walk_schema(child, "schema.$defs.{}".format(name), definitions)
    required = schema.get("required")
    if not isinstance(required, list) or len(required) != len(set(required)):
        raise EvidenceError("schema.required must be a unique array")
    if set(required) != TOP_LEVEL_KEYS:
        raise EvidenceError("schema top-level required fields drifted from collector")
    properties = schema.get("properties")
    if not isinstance(properties, dict) or set(properties) != TOP_LEVEL_KEYS:
        raise EvidenceError("schema top-level properties drifted from collector")
    item_schema = properties.get("items", {}).get("items")
    if not isinstance(item_schema, dict):
        raise EvidenceError("schema items definition is missing")
    if set(item_schema.get("required", [])) != ITEM_KEYS:
        raise EvidenceError("schema item required fields drifted from collector")
    if set(item_schema.get("properties", {})) != ITEM_KEYS:
        raise EvidenceError("schema item properties drifted from collector")
    nested_contracts = {
        "source_document": SOURCE_DOCUMENT_KEYS,
        "source_ref": SOURCE_REF_KEYS,
        "producer": PRODUCER_KEYS,
        "authorization": AUTHORIZATION_KEYS,
        "scope_exclusion": EXCLUSION_KEYS,
        "workstation_observation": OBSERVATION_KEYS,
        "evidence": EVIDENCE_KEYS,
    }
    for name, expected in nested_contracts.items():
        definition = definitions.get(name)
        if not isinstance(definition, dict):
            raise EvidenceError("schema.$defs.{} is missing".format(name))
        if set(definition.get("required", [])) != expected:
            raise EvidenceError("schema {} required fields drifted from collector".format(name))
        if set(definition.get("properties", {})) != expected:
            raise EvidenceError("schema {} properties drifted from collector".format(name))
    checks = (
        (schema["properties"]["schema_version"].get("const"), SCHEMA_VERSION, "schema_version const"),
        (schema["properties"]["contract"].get("const"), CONTRACT, "contract const"),
        (schema["properties"]["scope"].get("const"), SCOPE, "scope const"),
        (set(schema["properties"]["status"].get("enum", [])), TOP_STATUSES, "top status enum"),
        (set(item_schema["properties"]["status"].get("enum", [])), ITEM_STATUSES, "item status enum"),
        (set(item_schema["properties"]["stage"].get("enum", [])), STAGES, "stage enum"),
        (set(item_schema["properties"]["roles"]["items"].get("enum", [])), ROLES, "roles enum"),
        (set(item_schema["properties"]["category"].get("enum", [])), CATEGORIES, "category enum"),
        (set(item_schema["properties"]["supplier_kind"].get("enum", [])), SUPPLIER_KINDS, "supplier enum"),
        (set(item_schema["properties"]["sensitivity"].get("enum", [])), SENSITIVITIES, "sensitivity enum"),
        (set(item_schema["properties"]["artifact_kind"].get("enum", [])), ARTIFACT_KINDS, "artifact enum"),
        (set(definitions["workstation_observation"]["properties"]["result"].get("enum", [])), OBSERVATION_RESULTS, "observation enum"),
        (set(definitions["evidence"]["properties"]["kind"].get("enum", [])), EVIDENCE_KINDS, "evidence kind enum"),
        (definitions["id"].get("pattern"), SAFE_ID_PATTERN, "id pattern"),
        (definitions["sha256"].get("pattern"), HEX64_PATTERN, "SHA-256 pattern"),
        (definitions["git_oid"].get("pattern"), GIT_OID_PATTERN, "Git object pattern"),
    )
    for actual, expected, label in checks:
        if actual != expected:
            raise EvidenceError("schema {} drifted from collector".format(label))


def _validate_source_ref(value: Any, label: str) -> None:
    record = _require_exact_keys(value, SOURCE_REF_KEYS, label)
    _require_string(record["path"], label + ".path")
    start = _require_int(record["line_start"], label + ".line_start", 1)
    end = _require_int(record["line_end"], label + ".line_end", 1)
    if end < start:
        raise EvidenceError("{} line range is reversed".format(label))


def _validate_evidence(value: Any, label: str) -> None:
    record = _require_exact_keys(value, EVIDENCE_KEYS, label)
    path = _require_string(record["path"], label + ".path")
    if not Path(path).is_absolute() or os.path.normpath(path) != path:
        raise EvidenceError("{}.path must be canonical and absolute".format(label))
    if record["kind"] not in {"file", "directory"}:
        raise EvidenceError("{}.kind is invalid".format(label))
    _require_sha(record["sha256"], label + ".sha256")
    _require_int(record["size_bytes"], label + ".size_bytes")
    mode = _require_string(record["mode"], label + ".mode")
    if not re.fullmatch(r"0[0-7]{3}", mode):
        raise EvidenceError("{}.mode must be four octal digits".format(label))
    _require_int(record["uid"], label + ".uid")
    _require_int(record["gid"], label + ".gid")
    _require_utc(record["captured_at_utc"], label + ".captured_at_utc")
    _require_int(record["member_count"], label + ".member_count")


def validate_manifest(
    value: Any,
    allow_verified: bool = True,
    expected_template: Optional[Mapping[str, Any]] = None,
    expected_template_sha256: Optional[str] = None,
) -> Mapping[str, Any]:
    record = _require_exact_keys(value, TOP_LEVEL_KEYS, "manifest")
    if record["schema_version"] != SCHEMA_VERSION or type(record["schema_version"]) is not int:
        raise EvidenceError("manifest.schema_version is invalid")
    if record["contract"] != CONTRACT or record["scope"] != SCOPE:
        raise EvidenceError("manifest contract or scope is invalid")
    _require_utc(record["created_at_utc"], "manifest.created_at_utc")
    if record["status"] not in TOP_STATUSES:
        raise EvidenceError("manifest.status is invalid")
    authorized = _require_bool(record["deployment_authorized"], "manifest.deployment_authorized")
    if _require_bool(record["secret_material_redacted"], "manifest.secret_material_redacted") is not True:
        raise EvidenceError("manifest.secret_material_redacted must be true")
    approved_sha = record["approved_sha"]
    if approved_sha is not None:
        approved_sha = _require_git_oid(approved_sha, "manifest.approved_sha")

    sources = record["source_documents"]
    if not isinstance(sources, list) or len(sources) < 2:
        raise EvidenceError("manifest.source_documents must contain at least two records")
    source_paths = []
    referenced_paths = set()
    for index, source in enumerate(sources):
        label = "manifest.source_documents[{}]".format(index)
        source_record = _require_exact_keys(source, SOURCE_DOCUMENT_KEYS, label)
        source_paths.append(_require_string(source_record["path"], label + ".path"))
        _require_sha(source_record["sha256"], label + ".sha256")
        _require_string(source_record["purpose"], label + ".purpose")
    if len(source_paths) != len(set(source_paths)):
        raise EvidenceError("manifest.source_documents contains duplicate paths")

    producer = record["producer"]
    if producer is not None:
        producer_record = _require_exact_keys(producer, PRODUCER_KEYS, "manifest.producer")
        for key in ("collector_path", "schema_path", "template_path"):
            _require_string(producer_record[key], "manifest.producer." + key)
        for key in ("collector_sha256", "schema_sha256", "template_sha256", "collector_closure_sha256"):
            _require_sha(producer_record[key], "manifest.producer." + key)
        _require_git_oid(producer_record["repository_head"], "manifest.producer.repository_head")
        _require_bool(producer_record["repository_clean"], "manifest.producer.repository_clean")

    authorization = record["authorization"]
    if authorization is not None:
        auth = _require_exact_keys(authorization, AUTHORIZATION_KEYS, "manifest.authorization")
        if auth["method"] != "external-auditor-attestation":
            raise EvidenceError("manifest.authorization.method is invalid")
        _require_git_oid(auth["approved_sha"], "manifest.authorization.approved_sha")
        attestation_text = _require_string(auth["attestation_path"], "manifest.authorization.attestation_path")
        if not Path(attestation_text).is_absolute() or os.path.normpath(attestation_text) != attestation_text:
            raise EvidenceError("manifest.authorization.attestation_path must be canonical and absolute")
        _require_sha(auth["attestation_sha256"], "manifest.authorization.attestation_sha256")
        _require_string(auth["signer"], "manifest.authorization.signer")
        _require_utc(auth["signed_at_utc"], "manifest.authorization.signed_at_utc")

    exclusions = record["scope_exclusions"]
    if not isinstance(exclusions, list) or not exclusions:
        raise EvidenceError("manifest.scope_exclusions must be non-empty")
    exclusion_ids = []
    for index, exclusion in enumerate(exclusions):
        label = "manifest.scope_exclusions[{}]".format(index)
        item = _require_exact_keys(exclusion, EXCLUSION_KEYS, label)
        exclusion_ids.append(_require_string(item["id"], label + ".id"))
        _require_string(item["reason"], label + ".reason")
        refs = item["source_refs"]
        if not isinstance(refs, list) or not refs:
            raise EvidenceError(label + ".source_refs must be non-empty")
        for ref_index, ref in enumerate(refs):
            _validate_source_ref(ref, "{}.source_refs[{}]".format(label, ref_index))
            referenced_paths.add(ref["path"])
    if len(exclusion_ids) != len(set(exclusion_ids)):
        raise EvidenceError("manifest.scope_exclusions contains duplicate ids")

    observations = record["workstation_observations"]
    if not isinstance(observations, list):
        raise EvidenceError("manifest.workstation_observations must be an array")
    observation_ids = []
    for index, observation in enumerate(observations):
        label = "manifest.workstation_observations[{}]".format(index)
        item = _require_exact_keys(observation, OBSERVATION_KEYS, label)
        observation_ids.append(_require_string(item["id"], label + ".id"))
        _require_string(item["relates_to"], label + ".relates_to")
        _require_string(item["path"], label + ".path")
        if item["result"] not in OBSERVATION_RESULTS:
            raise EvidenceError(label + ".result is invalid")
        if item["kind"] is not None and item["kind"] not in EVIDENCE_KINDS:
            raise EvidenceError(label + ".kind is invalid")
        if item["mode"] is not None and not re.fullmatch(r"0[0-7]{3}", _require_string(item["mode"], label + ".mode")):
            raise EvidenceError(label + ".mode is invalid")
        if item["size_bytes"] is not None:
            _require_int(item["size_bytes"], label + ".size_bytes")
        _require_sha(item["sha256"], label + ".sha256", nullable=True)
        _require_utc(item["captured_at_utc"], label + ".captured_at_utc")
        _require_string(item["note"], label + ".note")
    if len(observation_ids) != len(set(observation_ids)):
        raise EvidenceError("manifest.workstation_observations contains duplicate ids")

    items = record["items"]
    if not isinstance(items, list) or not items:
        raise EvidenceError("manifest.items must be non-empty")
    ids = []
    required_statuses = []
    for index, item_value in enumerate(items):
        label = "manifest.items[{}]".format(index)
        item = _require_exact_keys(item_value, ITEM_KEYS, label)
        item_id = _require_string(item["id"], label + ".id")
        if not SAFE_ID_RE.fullmatch(item_id):
            raise EvidenceError(label + ".id has an unsafe shape")
        ids.append(item_id)
        if item["stage"] not in STAGES:
            raise EvidenceError(label + ".stage is invalid")
        roles = _require_string_list(item["roles"], label + ".roles")
        if not set(roles) <= ROLES:
            raise EvidenceError(label + ".roles contains an invalid role")
        if item["category"] not in CATEGORIES:
            raise EvidenceError(label + ".category is invalid")
        if item["supplier_kind"] not in SUPPLIER_KINDS:
            raise EvidenceError(label + ".supplier_kind is invalid")
        if item["sensitivity"] not in SENSITIVITIES:
            raise EvidenceError(label + ".sensitivity is invalid")
        if item["artifact_kind"] not in ARTIFACT_KINDS:
            raise EvidenceError(label + ".artifact_kind is invalid")
        required = _require_bool(item["required"], label + ".required")
        _require_bool(item["owner_only"], label + ".owner_only")
        if item["status"] not in ITEM_STATUSES:
            raise EvidenceError(label + ".status is invalid")
        if item["status"] == VERIFIED and not allow_verified:
            raise EvidenceError(label + " claims VERIFIED in a collector input")
        refs = item["source_refs"]
        if not isinstance(refs, list) or not refs:
            raise EvidenceError(label + ".source_refs must be non-empty")
        for ref_index, ref in enumerate(refs):
            _validate_source_ref(ref, "{}.source_refs[{}]".format(label, ref_index))
            referenced_paths.add(ref["path"])
        _require_string(item["requirement"], label + ".requirement")
        _require_string_list(item["required_evidence"], label + ".required_evidence")
        candidates = _require_string_list(item["candidate_paths"], label + ".candidate_paths", nonempty=False)
        for candidate in candidates:
            if not Path(candidate).is_absolute() or os.path.normpath(candidate) != candidate:
                raise EvidenceError(label + ".candidate_paths must be canonical absolute paths")
        _require_string_list(item["depends_on"], label + ".depends_on", nonempty=False)
        if item["evidence"] is not None:
            _validate_evidence(item["evidence"], label + ".evidence")
            if item["status"] == PENDING:
                raise EvidenceError(label + " has evidence but remains pending")
        elif item["status"] != PENDING:
            raise EvidenceError(label + " has a non-pending status without evidence")
        if item["missing_reason"] is not None:
            _require_string(item["missing_reason"], label + ".missing_reason")
        if item["status"] == PENDING and not item["missing_reason"]:
            raise EvidenceError(label + ".missing_reason is required while pending")
        _require_string(item["required_action"], label + ".required_action")
        if required:
            required_statuses.append(item["status"])
    if len(ids) != len(set(ids)):
        raise EvidenceError("manifest.items contains duplicate ids")
    id_set = set(ids)
    if not referenced_paths <= set(source_paths):
        raise EvidenceError("source references are not pinned in source_documents: {}".format(sorted(referenced_paths - set(source_paths))))
    for index, observation in enumerate(observations):
        if observation["relates_to"] not in id_set:
            raise EvidenceError("manifest.workstation_observations[{}] relates_to an unknown item".format(index))
    item_by_id = {item["id"]: item for item in items}
    for index, item in enumerate(items):
        unknown_dependencies = set(item["depends_on"]) - id_set
        if unknown_dependencies:
            raise EvidenceError("manifest.items[{}] has unknown dependencies {}".format(index, sorted(unknown_dependencies)))
        for dependency in item["depends_on"]:
            if STAGE_RANK[item_by_id[dependency]["stage"]] > STAGE_RANK[item["stage"]]:
                raise EvidenceError("manifest.items[{}] depends on a later deployment stage".format(index))

    visiting = set()
    visited = set()

    def visit(item_id: str) -> None:
        if item_id in visiting:
            raise EvidenceError("manifest dependency graph contains a cycle at {}".format(item_id))
        if item_id in visited:
            return
        visiting.add(item_id)
        for dependency in item_by_id[item_id]["depends_on"]:
            visit(dependency)
        visiting.remove(item_id)
        visited.add(item_id)

    for item_id in ids:
        visit(item_id)

    if expected_template is not None:
        expected_items = {item["id"]: item for item in expected_template["items"]}
        if set(item_by_id) != set(expected_items):
            raise EvidenceError("manifest item IDs differ from the committed owner-input inventory")
        for item_id, expected_item in expected_items.items():
            actual_item = item_by_id[item_id]
            for key in IMMUTABLE_ITEM_KEYS:
                if actual_item[key] != expected_item[key]:
                    raise EvidenceError(
                        "manifest item {} field {} differs from the committed owner-input inventory".format(
                            item_id, key
                        )
                    )
        for key in ("source_documents", "scope_exclusions", "workstation_observations"):
            if record[key] != expected_template[key]:
                raise EvidenceError("manifest {} differs from the committed owner-input inventory".format(key))
        if producer is not None and expected_template_sha256 is not None:
            if producer["template_sha256"] != expected_template_sha256:
                raise EvidenceError("manifest producer is not bound to the committed owner-input inventory")

    if CONFLICT in required_statuses:
        expected_top_status = CONFLICT
    elif PENDING in required_statuses:
        expected_top_status = PENDING
    elif required_statuses and all(status == VERIFIED for status in required_statuses):
        expected_top_status = VERIFIED
    else:
        expected_top_status = PRESENT
    if record["status"] != expected_top_status:
        raise EvidenceError("manifest top status does not match required item states")

    if not allow_verified and (record["status"] == VERIFIED or authorized or authorization is not None):
        raise EvidenceError("collector input may not claim authorization or verified status")
    if authorized:
        if record["status"] != VERIFIED or authorization is None or approved_sha is None or producer is None:
            raise EvidenceError("deployment authorization lacks verified status, approved SHA, or auditor attestation")
        if authorization["approved_sha"] != approved_sha:
            raise EvidenceError("authorization approved SHA does not match manifest")
        if producer["repository_head"] != approved_sha or not producer["repository_clean"]:
            raise EvidenceError("deployment authorization requires the clean producer repository at the approved SHA")
        if any(status != VERIFIED for status in required_statuses):
            raise EvidenceError("deployment authorization requires every required item to be VERIFIED")
        attestation_path = Path(authorization["attestation_path"])
        attestation, _ = _read_stable_file(attestation_path, owner_only=False)
        if sha256_bytes(attestation) != authorization["attestation_sha256"]:
            raise EvidenceError("external auditor attestation digest mismatch")
    elif record["status"] == VERIFIED:
        raise EvidenceError("VERIFIED manifest must explicitly carry deployment authorization")
    elif authorization is not None:
        raise EvidenceError("auditor authorization may appear only on an authorized VERIFIED manifest")
    return record


def validate_bindings(value: Any, template_ids: Iterable[str]) -> Mapping[str, Any]:
    record = _require_exact_keys(value, BINDINGS_TOP_KEYS, "bindings")
    if record["schema_version"] != SCHEMA_VERSION or type(record["schema_version"]) is not int:
        raise EvidenceError("bindings.schema_version is invalid")
    if record["contract"] != BINDINGS_CONTRACT:
        raise EvidenceError("bindings.contract is invalid")
    claimed_approved_sha = record["claimed_approved_sha"]
    if claimed_approved_sha is not None:
        _require_git_oid(claimed_approved_sha, "bindings.claimed_approved_sha")
    if not isinstance(record["items"], list):
        raise EvidenceError("bindings.items must be an array")
    valid_ids = set(template_ids)
    seen = set()
    for index, binding_value in enumerate(record["items"]):
        label = "bindings.items[{}]".format(index)
        binding = _require_exact_keys(binding_value, BINDING_KEYS, label)
        binding_id = _require_string(binding["id"], label + ".id")
        if binding_id not in valid_ids:
            raise EvidenceError(label + " names an unknown input id")
        if binding_id in seen:
            raise EvidenceError(label + " duplicates an input id")
        seen.add(binding_id)
        path = binding["path"]
        if path is not None:
            path = _require_string(path, label + ".path")
            if not Path(path).is_absolute() or os.path.normpath(path) != path:
                raise EvidenceError(label + ".path must be canonical and absolute")
        _require_sha(binding["expected_sha256"], label + ".expected_sha256", nullable=True)
    return record


def _require_platform_guards() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise EvidenceError("O_NOFOLLOW and O_DIRECTORY are required; refusing degraded path checks")


def _identity(info: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
    )


def _open_parent(path: Path) -> Tuple[int, str]:
    _require_platform_guards()
    text = str(path)
    if not path.is_absolute() or os.path.normpath(text) != text or path.name in {"", ".", ".."}:
        raise EvidenceError("input path must be canonical and absolute")
    parts = path.parts
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parts[1:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            info = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, os.geteuid()}
                or info.st_mode & 0o022
            ):
                os.close(next_descriptor)
                raise EvidenceError("input ancestor is not a safe owned non-writable directory")
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1]
    except Exception:
        os.close(descriptor)
        raise


def _read_file_from_parent(parent_fd: int, name: str, owner_only: bool) -> Tuple[bytes, os.stat_result]:
    linked_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(linked_before.st_mode):
        raise EvidenceError("evidence input must be a regular file, not a symlink or special file")
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EvidenceError("evidence input must be a one-link regular file")
        if before.st_uid != os.geteuid():
            raise EvidenceError("evidence input must be owned by the collecting user")
        forbidden = 0o077 if owner_only else 0o022
        if before.st_mode & forbidden:
            raise EvidenceError("evidence input permissions are too broad")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _identity(linked_before) != _identity(before)
            or _identity(before) != _identity(after)
            or _identity(after) != _identity(linked)
        ):
            raise EvidenceError("evidence input changed during collection")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _read_stable_file(path: Path, owner_only: bool) -> Tuple[bytes, os.stat_result]:
    try:
        parent_fd, name = _open_parent(path)
        try:
            return _read_file_from_parent(parent_fd, name, owner_only)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise EvidenceError("cannot securely read evidence input: {}".format(exc)) from exc


def _collect_directory_fd(
    descriptor: int,
    prefix: PurePosixPath,
    owner_only: bool,
    records: List[Mapping[str, Any]],
) -> int:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise EvidenceError("evidence directory must be owned by the collecting user")
    forbidden = 0o077 if owner_only else 0o022
    if info.st_mode & forbidden:
        raise EvidenceError("evidence directory permissions are too broad")
    total = 0
    for name in sorted(os.listdir(descriptor)):
        if name in {"", ".", ".."} or "/" in name or "\x00" in name:
            raise EvidenceError("evidence directory contains an unsafe member name")
        member_info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        relative = str(prefix / name)
        if stat.S_ISDIR(member_info.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                child_before = os.fstat(child)
                records.append({
                    "path": relative + "/",
                    "kind": "directory",
                    "mode": "0{:03o}".format(stat.S_IMODE(child_before.st_mode)),
                    "size_bytes": 0,
                    "sha256": None,
                })
                total += _collect_directory_fd(child, prefix / name, owner_only, records)
                child_after = os.fstat(child)
                child_linked = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _identity(child_before) != _identity(child_after) or _identity(child_after) != _identity(child_linked):
                    raise EvidenceError("evidence subdirectory changed during collection")
            finally:
                os.close(child)
        elif stat.S_ISREG(member_info.st_mode):
            data, stable = _read_file_from_parent(descriptor, name, owner_only)
            records.append({
                "path": relative,
                "kind": "file",
                "mode": "0{:03o}".format(stat.S_IMODE(stable.st_mode)),
                "size_bytes": stable.st_size,
                "sha256": sha256_bytes(data),
            })
            total += stable.st_size
        else:
            raise EvidenceError("evidence directory contains a symlink or special file")
    return total


def _collect_directory(path: Path, owner_only: bool) -> Tuple[str, int, int, os.stat_result]:
    parent_fd, name = _open_parent(path)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            before = os.fstat(descriptor)
            records: List[Mapping[str, Any]] = []
            total = _collect_directory_fd(descriptor, PurePosixPath(), owner_only, records)
            after = os.fstat(descriptor)
            linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(before) != _identity(after) or _identity(after) != _identity(linked):
                raise EvidenceError("evidence directory changed during collection")
            if not records:
                raise EvidenceError("evidence directory must not be empty")
            return sha256_bytes(canonical_json_bytes(records)), total, len(records), after
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise EvidenceError("cannot securely read evidence directory: {}".format(exc)) from exc
    finally:
        os.close(parent_fd)


def collect_path(path: Path, artifact_kind: str, owner_only: bool) -> Mapping[str, Any]:
    captured = utc_now()
    if artifact_kind == "directory":
        digest, size, count, info = _collect_directory(path, owner_only)
        kind = "directory"
    else:
        data, info = _read_stable_file(path, owner_only)
        if not data:
            raise EvidenceError("evidence input must not be empty")
        digest, size, count, kind = sha256_bytes(data), info.st_size, 0, "file"
        if artifact_kind == "binary" and not info.st_mode & stat.S_IXUSR:
            raise EvidenceError("binary evidence input is not owner-executable")
    return {
        "path": str(path),
        "kind": kind,
        "sha256": digest,
        "size_bytes": size,
        "mode": "0{:03o}".format(stat.S_IMODE(info.st_mode)),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "captured_at_utc": captured,
        "member_count": count,
    }


def _git_identity() -> Tuple[str, bool]:
    try:
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), stderr=subprocess.DEVNULL
        ).decode("ascii").strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain=v1"], cwd=str(REPO_ROOT), stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise EvidenceError("cannot bind repository identity") from exc
    _require_git_oid(head, "repository HEAD")
    return head, not bool(dirty)


def _producer_record(
    template_bytes: bytes,
    schema_bytes: bytes,
    collector_bytes: bytes,
) -> Mapping[str, Any]:
    collector_sha = sha256_bytes(collector_bytes)
    schema_sha = sha256_bytes(schema_bytes)
    template_sha = sha256_bytes(template_bytes)
    closure = sha256_bytes(canonical_json_bytes({
        "collector_sha256": collector_sha,
        "schema_sha256": schema_sha,
        "template_sha256": template_sha,
    }))
    head, clean = _git_identity()
    return {
        "collector_path": "tools/deployment_owner_inputs.py",
        "collector_sha256": collector_sha,
        "schema_path": "tools/deployment_owner_inputs.schema.json",
        "schema_sha256": schema_sha,
        "template_path": "deploy/production-input-evidence/PENDING-OWNER-INPUT.json",
        "template_sha256": template_sha,
        "collector_closure_sha256": closure,
        "repository_head": head,
        "repository_clean": clean,
    }


def build_evidence(
    template: Mapping[str, Any],
    bindings: Mapping[str, Any],
    template_bytes: bytes,
    schema_bytes: bytes,
    collector_bytes: bytes,
) -> Mapping[str, Any]:
    if template["status"] == VERIFIED or template["deployment_authorized"] or template["authorization"] is not None:
        raise EvidenceError("collector refuses an authorized or verified template")
    by_id = {entry["id"]: entry for entry in bindings["items"]}
    output = json.loads(json.dumps(template))
    output["created_at_utc"] = utc_now()
    output["approved_sha"] = None
    output["producer"] = _producer_record(template_bytes, schema_bytes, collector_bytes)
    claimed_approved_sha = bindings["claimed_approved_sha"]
    if claimed_approved_sha is not None and claimed_approved_sha != output["producer"]["repository_head"]:
        raise EvidenceError("claimed approved SHA does not match the collecting repository HEAD")
    output["authorization"] = None
    output["deployment_authorized"] = False
    output["status"] = PENDING
    all_present = True
    for item in output["items"]:
        binding = by_id.get(item["id"])
        if binding is None or binding["path"] is None:
            all_present = False
            continue
        try:
            evidence = collect_path(Path(binding["path"]), item["artifact_kind"], item["owner_only"])
            item["evidence"] = evidence
            if binding["expected_sha256"] is not None and evidence["sha256"] != binding["expected_sha256"]:
                item["status"] = CONFLICT
                item["missing_reason"] = "Collected bytes disagree with the owner or authority supplied digest."
                item["required_action"] = "Stop and reconcile the exact bytes with the named supplier; do not update the expected digest to fit."
                all_present = False
            else:
                item["status"] = PRESENT
                item["missing_reason"] = None
        except (EvidenceError, OSError):
            item["status"] = PENDING
            item["evidence"] = None
            item["required_action"] = (
                item["required_action"]
                + " The bound artifact failed fail-closed collection; correct its custody, permissions, type, or binding and retry."
            )
            all_present = False
    required_items = [item for item in output["items"] if item["required"]]
    if any(item["status"] == CONFLICT for item in required_items):
        output["status"] = CONFLICT
    elif all_present:
        output["status"] = PRESENT
    validate_manifest(
        output,
        allow_verified=False,
        expected_template=template,
        expected_template_sha256=sha256_bytes(template_bytes),
    )
    return output


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    parent_fd, name = _open_parent(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise EvidenceError("output parent must be owned by the collecting user and not group/world writable")
        descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise EvidenceError("short write while creating evidence output")
                offset += written
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.geteuid():
                raise EvidenceError("output file permissions or ownership are wrong")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _create_output_dir(path: Path) -> None:
    parent_fd, name = _open_parent(path)
    try:
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise EvidenceError("output parent must be owned by the collecting user and not group/world writable")
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise EvidenceError("output directory already exists; refusing reuse")
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            os.fchmod(descriptor, 0o700)
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise EvidenceError("output directory is not owner-controlled mode 0700")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def write_evidence_directory(path: Path, evidence: Mapping[str, Any]) -> str:
    _create_output_dir(path)
    payload = canonical_json_bytes(evidence) + b"\n"
    digest = sha256_bytes(payload)
    try:
        _write_new_file(path / OUTPUT_NAME, payload, 0o600)
        _write_new_file(path / OUTPUT_DIGEST_NAME, (digest + "  " + OUTPUT_NAME + "\n").encode("ascii"), 0o600)
    except Exception:
        # Leave any partial output in place for inspection.  Reuse is forbidden.
        raise
    return digest


def init_bindings(template: Mapping[str, Any], output: Path) -> None:
    record = {
        "schema_version": SCHEMA_VERSION,
        "contract": BINDINGS_CONTRACT,
        "claimed_approved_sha": None,
        "items": [
            {"id": item["id"], "path": None, "expected_sha256": None}
            for item in template["items"]
        ],
    }
    _write_new_file(output, canonical_json_bytes(record) + b"\n", 0o600)


def load_schema_and_template() -> Tuple[Mapping[str, Any], Mapping[str, Any], bytes, bytes, bytes]:
    try:
        schema_bytes = SCHEMA_PATH.read_bytes()
        template_bytes = TEMPLATE_PATH.read_bytes()
        collector_bytes = COLLECTOR_PATH.read_bytes()
    except OSError as exc:
        raise EvidenceError("cannot read collector contract bytes: {}".format(exc)) from exc
    schema = strict_json_load_bytes(schema_bytes, "schema")
    validate_schema_contract(schema)
    template = strict_json_load_bytes(template_bytes, "pending owner input manifest")
    validate_manifest(template, allow_verified=False)
    return schema, template, template_bytes, schema_bytes, collector_bytes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate a manifest without granting authority")
    validate.add_argument("manifest", type=Path)
    initialize = subparsers.add_parser("init-bindings", help="write an owner-only bindings template")
    initialize.add_argument("output", type=Path)
    collect = subparsers.add_parser("collect", help="collect bound inputs into a new evidence directory")
    collect.add_argument("--bindings", type=Path, required=True)
    collect.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        _schema, template, template_bytes, schema_bytes, collector_bytes = load_schema_and_template()
        args = _parser().parse_args(argv)
        if args.command == "validate":
            manifest = strict_json_load(args.manifest, "manifest")
            validate_manifest(
                manifest,
                allow_verified=True,
                expected_template=template,
                expected_template_sha256=sha256_bytes(template_bytes),
            )
            print("STRUCTURALLY-VALID: status={} deployment_authorized={} no_authority_conferred=true".format(
                manifest["status"], str(manifest["deployment_authorized"]).lower()
            ))
            return 3 if manifest["deployment_authorized"] else 0
        if args.command == "init-bindings":
            init_bindings(template, args.output)
            print("WROTE bindings template with {} pending inputs".format(len(template["items"])))
            return 0
        if args.command == "collect":
            bindings = strict_json_load(args.bindings, "bindings", secure=True)
            validate_bindings(bindings, (item["id"] for item in template["items"]))
            evidence = build_evidence(template, bindings, template_bytes, schema_bytes, collector_bytes)
            digest = write_evidence_directory(args.output_dir, evidence)
            supplied = sum(item["status"] == PRESENT for item in evidence["items"])
            conflicts = sum(item["status"] == CONFLICT for item in evidence["items"])
            print("WROTE {} sha256={} present_unverified={} conflicts={} pending={} deployment_authorized=false".format(
                args.output_dir / OUTPUT_NAME,
                digest,
                supplied,
                conflicts,
                len(evidence["items"]) - supplied - conflicts,
            ))
            return 3
        raise EvidenceError("unknown command")
    except EvidenceError as exc:
        print("REFUSE: {}".format(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print("REFUSE: operating-system error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
