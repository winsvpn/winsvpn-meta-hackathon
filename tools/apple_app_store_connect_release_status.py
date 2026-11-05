#!/usr/bin/env python3
"""Audit and narrowly synchronize the live Win's VPN App Store Connect release."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import apple_app_store_connect_auth_probe as auth_probe


ROOT = Path(__file__).resolve().parents[1]
API_BASE = "https://api.appstoreconnect.apple.com"
APP_ID = auth_probe.EXPECTED_APP_ID
BUNDLE_ID = auth_probe.EXPECTED_BUNDLE_ID
LOCALE = "en-US"
MAX_RESPONSE_BYTES = 2_097_152
READ_CHUNK_BYTES = 65_536
REQUEST_TIMEOUT_SECONDS = 30
EXPECTED_PLATFORMS = {"IOS": "ios", "MAC_OS": "macos"}
RELEASE_MANIFEST = ROOT / "app_store/apple/artifacts/release_candidate.json"
PUBSPEC = ROOT / "pubspec.yaml"


class ReleaseStatusError(RuntimeError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "App Store Connect redirect refused",
            headers,
            fp,
        )


_AUTHENTICATED_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirectHandler(),
)
_RESOURCE_COMPONENT = re.compile(r"^[A-Za-z0-9._~-]+$")
_RESOURCE_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def _safe_api_path(path: str) -> str:
    if not isinstance(path, str):
        raise ReleaseStatusError("refusing a non-string App Store Connect path")
    parsed = urllib.parse.urlsplit(path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.path != path
        or not path.startswith(("/v1/", "/v2/"))
        or "//" in path
    ):
        raise ReleaseStatusError("refusing an unexpected App Store Connect path")
    components = path.split("/")[2:]
    if not components or any(
        not component or _RESOURCE_COMPONENT.fullmatch(component) is None
        for component in components
    ):
        raise ReleaseStatusError("refusing an unsafe App Store Connect path")
    return path


def _request_url(path: str, params: Mapping[str, str] | None = None) -> str:
    safe_path = _safe_api_path(path)
    query = ""
    if params:
        if not isinstance(params, Mapping):
            raise ReleaseStatusError("refusing malformed App Store Connect query data")
        pairs: list[tuple[str, str]] = []
        for key, value in params.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key + value)
            ):
                raise ReleaseStatusError("refusing unsafe App Store Connect query data")
            pairs.append((key, value))
        query = urllib.parse.urlencode(pairs)
    url = API_BASE + safe_path + (f"?{query}" if query else "")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.appstoreconnect.apple.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != safe_path
        or parsed.fragment
    ):
        raise ReleaseStatusError("refusing a noncanonical App Store Connect origin")
    return url


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseStatusError("App Store Connect JSON contains duplicate keys")
        result[key] = value
    return result


def _read_capped_response(response: Any, label: str) -> bytes:
    raw_length = response.headers.get("Content-Length")
    if raw_length is not None:
        try:
            declared_length = int(raw_length, 10)
        except (TypeError, ValueError) as exc:
            raise ReleaseStatusError(f"{label} has an invalid Content-Length") from exc
        if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
            raise ReleaseStatusError(f"{label} exceeded the size limit")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(READ_CHUNK_BYTES, MAX_RESPONSE_BYTES + 1 - total))
        if not isinstance(chunk, bytes):
            raise ReleaseStatusError(f"{label} returned non-byte response data")
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ReleaseStatusError(f"{label} exceeded the size limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if raw_length is not None and len(raw) != declared_length:
        raise ReleaseStatusError(f"{label} body length does not match Content-Length")
    return raw


def _resource_identity(resource: Any, label: str) -> tuple[str, str]:
    if not isinstance(resource, dict):
        raise ReleaseStatusError(f"{label} is not a JSON:API resource")
    resource_type = resource.get("type")
    resource_id = resource.get("id")
    if (
        not isinstance(resource_type, str)
        or _RESOURCE_TYPE.fullmatch(resource_type) is None
        or not isinstance(resource_id, str)
        or _RESOURCE_COMPONENT.fullmatch(resource_id) is None
    ):
        raise ReleaseStatusError(f"{label} has an invalid JSON:API identity")
    return resource_type, resource_id


def _validate_relationship_identities(resource: dict[str, Any], label: str) -> None:
    relationships = resource.get("relationships")
    if relationships is None:
        return
    if not isinstance(relationships, dict):
        raise ReleaseStatusError(f"{label} relationships are malformed")
    for name, relationship in relationships.items():
        if not isinstance(name, str) or not isinstance(relationship, dict):
            raise ReleaseStatusError(f"{label} relationship is malformed")
        data = relationship.get("data")
        if data is None:
            continue
        values = data if isinstance(data, list) else [data]
        seen: set[tuple[str, str]] = set()
        for item in values:
            identity = _resource_identity(item, f"{label} relationship {name}")
            if identity in seen:
                raise ReleaseStatusError(f"{label} relationship {name} is ambiguous")
            seen.add(identity)


def _validate_jsonapi_document(payload: Any, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or "data" not in payload or "errors" in payload:
        raise ReleaseStatusError(f"{label} returned an invalid JSON:API body")
    primary = payload["data"]
    primary_values: list[Any]
    if primary is None:
        primary_values = []
    elif isinstance(primary, list):
        primary_values = primary
    elif isinstance(primary, dict):
        primary_values = [primary]
    else:
        raise ReleaseStatusError(f"{label} returned malformed JSON:API data")
    seen_primary: set[tuple[str, str]] = set()
    for item in primary_values:
        identity = _resource_identity(item, f"{label} primary data")
        if identity in seen_primary:
            raise ReleaseStatusError(f"{label} returned duplicate primary resources")
        seen_primary.add(identity)
        _validate_relationship_identities(item, f"{label} primary resource")
    included = payload.get("included", [])
    if not isinstance(included, list):
        raise ReleaseStatusError(f"{label} returned malformed included resources")
    seen_included: set[tuple[str, str]] = set()
    for item in included:
        identity = _resource_identity(item, f"{label} included data")
        if identity in seen_included:
            raise ReleaseStatusError(f"{label} returned duplicate included resources")
        seen_included.add(identity)
        _validate_relationship_identities(item, f"{label} included resource")
    return payload


def _parse_jsonapi(raw: bytes, label: str) -> dict[str, Any]:
    if not raw:
        raise ReleaseStatusError(f"{label} returned an empty JSON body")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseStatusError(
                    f"{label} returned non-finite JSON value {value}"
                )
            ),
        )
    except ReleaseStatusError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseStatusError(f"{label} returned malformed JSON") from exc
    return _validate_jsonapi_document(payload, label)


def _encode_json(payload: dict[str, Any], label: str) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ReleaseStatusError(f"refusing malformed {label} JSON") from exc


def _require_single_response_resource(
    payload: dict[str, Any],
    expected_type: str,
    expected_id: str | None,
    label: str,
) -> dict[str, Any]:
    resource = payload.get("data")
    actual_type, actual_id = _resource_identity(resource, f"{label} response")
    if actual_type != expected_type or (
        expected_id is not None and actual_id != expected_id
    ):
        raise ReleaseStatusError(f"{label} returned another JSON:API resource")
    assert isinstance(resource, dict)
    return resource


def _release_identity() -> tuple[str, str]:
    """Load the active Apple version/build from the hash-pinned candidate manifest."""
    try:
        manifest = json.loads(RELEASE_MANIFEST.read_text(encoding="utf-8"))
        pubspec_text = PUBSPEC.read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseStatusError("could not load the active Apple release identity") from exc
    if not isinstance(manifest, dict):
        raise ReleaseStatusError("Apple release candidate manifest must be a JSON object")
    version = str(manifest.get("app_version") or "")
    build = str(manifest.get("build_number") or "")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version) is None:
        raise ReleaseStatusError("Apple release candidate version is invalid")
    if re.fullmatch(r"[1-9][0-9]*", build) is None:
        raise ReleaseStatusError("Apple release candidate build number is invalid")
    pubspec_match = re.search(
        r"(?m)^version:\s*([^+\s]+)\+([1-9][0-9]*)\s*$",
        pubspec_text,
    )
    if pubspec_match is None or pubspec_match.groups() != (version, build):
        raise ReleaseStatusError(
            "Apple release candidate identity does not match pubspec.yaml"
        )
    return version, build


APP_VERSION, BUILD_NUMBER = _release_identity()


def _read_metadata(name: str) -> str:
    path = ROOT / "app_store" / "apple" / "metadata" / LOCALE / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ReleaseStatusError(f"could not read {path.relative_to(ROOT)}") from exc


EXPECTED_VERSION_LOCALIZATION = {
    "description": _read_metadata("description.txt"),
    "keywords": _read_metadata("keywords.txt"),
    "marketingUrl": _read_metadata("marketing_url.txt"),
    "promotionalText": _read_metadata("promotional_text.txt"),
    "supportUrl": _read_metadata("support_url.txt"),
}
EXPECTED_PRIVACY_URL = _read_metadata("privacy_url.txt")


class AppStoreConnectClient:
    def __init__(self, token: str) -> None:
        if (
            not isinstance(token, str)
            or re.fullmatch(
                r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token
            )
            is None
        ):
            raise ReleaseStatusError("refusing an invalid App Store Connect bearer token")
        self._token = token

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: bytes | None = None,
        expected_status: int,
        expect_json: bool,
        allow_missing_relationship: bool = False,
        label: str,
    ) -> dict[str, Any] | None:
        if method not in {"GET", "PATCH", "POST", "DELETE"}:
            raise ReleaseStatusError("refusing an unsupported App Store Connect method")
        if method in {"GET", "DELETE"} and body is not None:
            raise ReleaseStatusError("refusing a body on this App Store Connect method")
        if method != "GET" and params:
            raise ReleaseStatusError("refusing query parameters on an App Store mutation")
        url = _request_url(path, params)
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "wins-vpn-release-status/1",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url,
            method=method,
            data=body,
            headers=headers,
        )
        try:
            response = _AUTHENTICATED_OPENER.open(
                request, timeout=REQUEST_TIMEOUT_SECONDS
            )
        except urllib.error.HTTPError as exc:
            try:
                response_url = exc.geturl()
                if response_url != url:
                    raise ReleaseStatusError(
                        f"{label} HTTP error URL differs from the intended request"
                    ) from exc
                if 300 <= exc.code <= 399:
                    raise ReleaseStatusError(
                        f"{label} refused HTTP redirect {exc.code}"
                    ) from exc
                if allow_missing_relationship and method == "GET" and exc.code == 404:
                    return {"data": None}
                raise ReleaseStatusError(
                    f"{label} returned HTTP {exc.code} for {path}"
                ) from exc
            finally:
                exc.close()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ReleaseStatusError(f"{label} failed for {path}") from exc
        with response:
            response_url = response.geturl()
            if response_url != url:
                raise ReleaseStatusError(
                    f"{label} response URL differs from the intended request"
                )
            status = getattr(response, "status", None)
            if type(status) is not int or status != expected_status:
                raise ReleaseStatusError(f"{label} returned HTTP {status}")
            if expect_json:
                content_type = str(response.headers.get("Content-Type") or "")
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type not in {"application/json", "application/vnd.api+json"}:
                    raise ReleaseStatusError(f"{label} returned a non-JSON content type")
            raw = _read_capped_response(response, label)
        if not expect_json:
            if raw:
                raise ReleaseStatusError(f"{label} returned an unexpected response body")
            return None
        return _parse_jsonapi(raw, label)

    def get(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        allow_missing_relationship: bool = False,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            path,
            params=params,
            expected_status=200,
            expect_json=True,
            allow_missing_relationship=allow_missing_relationship,
            label="App Store Connect request",
        )
        assert payload is not None
        return payload

    def patch_attributes(
        self,
        path: str,
        resource_type: str,
        resource_id: str,
        attributes: dict[str, Any],
    ) -> dict[str, Any]:
        expected_path = f"/v1/{resource_type}/{resource_id}"
        if (
            path != expected_path
            or not isinstance(resource_type, str)
            or _RESOURCE_TYPE.fullmatch(resource_type) is None
            or not isinstance(resource_id, str)
            or _RESOURCE_COMPONENT.fullmatch(resource_id) is None
            or not isinstance(attributes, dict)
        ):
            raise ReleaseStatusError("refusing an unexpected mutation target")
        body = _encode_json(
            {
                "data": {
                    "type": resource_type,
                    "id": resource_id,
                    "attributes": attributes,
                }
            },
            "App Store Connect mutation",
        )
        payload = self._request(
            "PATCH",
            path,
            body=body,
            expected_status=200,
            expect_json=True,
            label="App Store Connect mutation",
        )
        assert payload is not None
        _require_single_response_resource(
            payload, resource_type, resource_id, "App Store Connect mutation"
        )
        return payload

    def post_resource(
        self,
        path: str,
        resource_type: str,
        attributes: dict[str, Any],
        relationships: dict[str, Any],
    ) -> dict[str, Any]:
        if (
            path != f"/v1/{resource_type}"
            or not isinstance(resource_type, str)
            or _RESOURCE_TYPE.fullmatch(resource_type) is None
            or not isinstance(attributes, dict)
            or not isinstance(relationships, dict)
        ):
            raise ReleaseStatusError("refusing an unexpected creation target")
        _validate_relationship_identities(
            {"relationships": relationships}, "App Store Connect creation"
        )
        body = _encode_json(
            {
                "data": {
                    "type": resource_type,
                    "attributes": attributes,
                    "relationships": relationships,
                }
            },
            "App Store Connect creation",
        )
        payload = self._request(
            "POST",
            path,
            body=body,
            expected_status=201,
            expect_json=True,
            label="App Store Connect creation",
        )
        assert payload is not None
        _require_single_response_resource(
            payload, resource_type, None, "App Store Connect creation"
        )
        return payload

    def delete_resource(
        self,
        path: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        expected_path = f"/v1/{resource_type}/{resource_id}"
        if (
            path != expected_path
            or not isinstance(resource_type, str)
            or _RESOURCE_TYPE.fullmatch(resource_type) is None
            or not isinstance(resource_id, str)
            or _RESOURCE_COMPONENT.fullmatch(resource_id) is None
        ):
            raise ReleaseStatusError("refusing an unexpected deletion target")
        self._request(
            "DELETE",
            path,
            expected_status=204,
            expect_json=False,
            label="App Store Connect deletion",
        )

    def patch_relationship(
        self,
        parent_type: str,
        parent_id: str,
        relationship_name: str,
        related_type: str,
        related_id: str,
    ) -> None:
        allowed = {
            ("appStoreVersions", "build"): "builds",
        }
        if (
            not isinstance(parent_id, str)
            or _RESOURCE_COMPONENT.fullmatch(parent_id) is None
            or not isinstance(related_id, str)
            or _RESOURCE_COMPONENT.fullmatch(related_id) is None
            or allowed.get((parent_type, relationship_name)) != related_type
        ):
            raise ReleaseStatusError("refusing an unexpected relationship mutation")
        path = f"/v1/{parent_type}/{parent_id}/relationships/{relationship_name}"
        body = _encode_json(
            {"data": {"type": related_type, "id": related_id}},
            "App Store Connect relationship mutation",
        )
        self._request(
            "PATCH",
            path,
            body=body,
            expected_status=204,
            expect_json=False,
            label="App Store Connect relationship mutation",
        )

    def create_app_availability(
        self,
        payload: dict[str, Any],
        expected_territory_ids: set[str],
    ) -> dict[str, Any]:
        data = payload.get("data")
        included = payload.get("included")
        if (
            set(payload) != {"data", "included"}
            or not isinstance(data, dict)
            or set(data) != {"type", "attributes", "relationships"}
            or not isinstance(included, list)
        ):
            raise ReleaseStatusError("refusing malformed app availability data")
        if data.get("type") != "appAvailabilities" or data.get("attributes") != {
            "availableInNewTerritories": True
        }:
            raise ReleaseStatusError("refusing unexpected app availability attributes")
        relationships = data.get("relationships")
        if not isinstance(relationships, dict):
            raise ReleaseStatusError("refusing app availability without relationships")
        _validate_relationship_identities(data, "App Store Connect availability")
        app_relationship = relationships.get("app")
        territory_relationship = relationships.get("territoryAvailabilities")
        if not isinstance(app_relationship, dict) or not isinstance(
            territory_relationship, dict
        ):
            raise ReleaseStatusError("refusing incomplete app availability relationships")
        app_data = app_relationship.get("data")
        relationship_data = territory_relationship.get("data")
        if app_data != {"type": "apps", "id": APP_ID} or not isinstance(
            relationship_data, list
        ):
            raise ReleaseStatusError("refusing availability for an unexpected app")
        relationship_ids = {
            str(item.get("id") or "")
            for item in relationship_data
            if isinstance(item, dict) and item.get("type") == "territoryAvailabilities"
        }
        included_ids: set[str] = set()
        territory_ids: set[str] = set()
        for item in included:
            if (
                not isinstance(item, dict)
                or set(item) != {"type", "id", "attributes", "relationships"}
                or item.get("type") != "territoryAvailabilities"
            ):
                raise ReleaseStatusError("refusing an invalid included availability")
            _resource_identity(item, "included app availability")
            _validate_relationship_identities(item, "included app availability")
            local_id = str(item.get("id") or "")
            if not local_id or local_id in included_ids:
                raise ReleaseStatusError("refusing a duplicate included availability")
            if item.get("attributes") != {
                "available": True,
                "preOrderEnabled": False,
            }:
                raise ReleaseStatusError("refusing preorder or unavailable territory data")
            item_relationships = item.get("relationships")
            if not isinstance(item_relationships, dict):
                raise ReleaseStatusError("refusing availability without a territory")
            territory = item_relationships.get("territory")
            territory_data = territory.get("data") if isinstance(territory, dict) else None
            if not isinstance(territory_data, dict) or territory_data.get(
                "type"
            ) != "territories":
                raise ReleaseStatusError("refusing an invalid territory relationship")
            territory_id = str(territory_data.get("id") or "")
            if not territory_id or territory_id in territory_ids:
                raise ReleaseStatusError("refusing a duplicate territory availability")
            included_ids.add(local_id)
            territory_ids.add(territory_id)
        if (
            relationship_ids != included_ids
            or territory_ids != expected_territory_ids
            or len(relationship_data) != len(expected_territory_ids)
            or len(included) != len(expected_territory_ids)
        ):
            raise ReleaseStatusError("refusing an incomplete territory availability set")

        body = _encode_json(payload, "App Store Connect availability creation")
        result = self._request(
            "POST",
            "/v2/appAvailabilities",
            body=body,
            expected_status=201,
            expect_json=True,
            label="App Store Connect availability creation",
        )
        assert result is not None
        _require_single_response_resource(
            result,
            "appAvailabilities",
            None,
            "App Store Connect availability creation",
        )
        return result


def _collection(payload: dict[str, Any], label: str) -> list[dict[str, Any]]:
    data = payload.get("data")
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ReleaseStatusError(f"{label} response is not a JSON:API collection")
    return data


def _resource_or_none(
    payload: dict[str, Any], label: str
) -> dict[str, Any] | None:
    data = payload.get("data")
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ReleaseStatusError(f"{label} response is not a JSON:API resource")
    return data


def _attributes(resource: dict[str, Any], label: str) -> dict[str, Any]:
    attributes = resource.get("attributes")
    if not isinstance(attributes, dict):
        raise ReleaseStatusError(f"{label} resource has no attributes")
    return attributes


def _relationship_data(
    resource: dict[str, Any], relationship_name: str, label: str
) -> dict[str, Any]:
    relationships = resource.get("relationships")
    if not isinstance(relationships, dict):
        raise ReleaseStatusError(f"{label} resource has no relationships")
    relationship = relationships.get(relationship_name)
    if not isinstance(relationship, dict):
        raise ReleaseStatusError(
            f"{label} resource has no {relationship_name} relationship"
        )
    data = relationship.get("data")
    if not isinstance(data, dict):
        raise ReleaseStatusError(
            f"{label} resource has no {relationship_name} relationship data"
        )
    return data


def _exactly_one(
    resources: list[dict[str, Any]], label: str
) -> dict[str, Any]:
    if len(resources) != 1:
        raise ReleaseStatusError(f"expected exactly one {label}, found {len(resources)}")
    return resources[0]


def _load_client() -> AppStoreConnectClient:
    key_path = auth_probe.require_private_external_key(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_PATH", "")
    )
    key_id = auth_probe.require_key_id(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_ID", "")
    )
    issuer_id = auth_probe.require_issuer_id(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID", "")
    )
    return AppStoreConnectClient(
        auth_probe.create_token(key_path, key_id, issuer_id)
    )


def _version_localization(
    client: AppStoreConnectClient, version_id: str
) -> dict[str, Any]:
    payload = client.get(
        f"/v1/appStoreVersions/{version_id}/appStoreVersionLocalizations",
        {"filter[locale]": LOCALE, "limit": "10"},
    )
    return _exactly_one(_collection(payload, "version localization"), LOCALE)


def _screenshot_count(
    client: AppStoreConnectClient, localization_id: str
) -> tuple[int, list[str]]:
    sets = _collection(
        client.get(
            f"/v1/appStoreVersionLocalizations/{localization_id}/appScreenshotSets",
            {"limit": "50"},
        ),
        "screenshot sets",
    )
    display_types: list[str] = []
    total = 0
    for screenshot_set in sets:
        screenshot_set_id = str(screenshot_set.get("id") or "")
        attributes = _attributes(screenshot_set, "screenshot set")
        display_type = str(attributes.get("screenshotDisplayType") or "")
        if display_type:
            display_types.append(display_type)
        screenshots = _collection(
            client.get(
                f"/v1/appScreenshotSets/{screenshot_set_id}/appScreenshots",
                {"limit": "50"},
            ),
            "screenshots",
        )
        total += len(screenshots)
    return total, sorted(display_types)


def _app_info_status(client: AppStoreConnectClient) -> dict[str, Any]:
    infos = _collection(
        client.get(f"/v1/apps/{APP_ID}/appInfos", {"limit": "10"}),
        "app infos",
    )
    if not infos:
        raise ReleaseStatusError("App Store Connect returned no app info resource")
    localized: list[dict[str, Any]] = []
    for info in infos:
        info_id = str(info.get("id") or "")
        localizations = _collection(
            client.get(
                f"/v1/appInfos/{info_id}/appInfoLocalizations",
                {"filter[locale]": LOCALE, "limit": "10"},
            ),
            "app info localizations",
        )
        localized.extend(localizations)
    localization = _exactly_one(localized, f"{LOCALE} app info localization")
    attributes = _attributes(localization, "app info localization")
    actual_url = attributes.get("privacyPolicyUrl")
    return {
        "localization_id": localization.get("id"),
        "privacy_policy_url": actual_url,
        "expected_privacy_policy_url": EXPECTED_PRIVACY_URL,
        "privacy_policy_url_matches": actual_url == EXPECTED_PRIVACY_URL,
    }


def _active_territory_ids(client: AppStoreConnectClient) -> set[str]:
    payload = client.get("/v1/territories", {"limit": "200"})
    resources = _collection(payload, "territories")
    links = payload.get("links")
    if isinstance(links, dict) and links.get("next"):
        raise ReleaseStatusError("active territory response unexpectedly requires paging")
    territory_ids = {str(resource.get("id") or "") for resource in resources}
    if "" in territory_ids or len(territory_ids) != len(resources):
        raise ReleaseStatusError("active territory response has missing or duplicate IDs")
    return territory_ids


def _price_status(
    client: AppStoreConnectClient, active_territories: set[str]
) -> dict[str, Any]:
    schedule = _resource_or_none(
        client.get(f"/v1/apps/{APP_ID}/appPriceSchedule"),
        "app price schedule",
    )
    if schedule is None:
        return {
            "configured": False,
            "entry_count": 0,
            "territory_count": 0,
            "active_territory_count": len(active_territories),
            "all_free": False,
            "missing_territories": sorted(active_territories),
            "unexpected_territories": [],
        }
    schedule_id = str(schedule.get("id") or "")
    if not schedule_id:
        raise ReleaseStatusError("app price schedule has no resource ID")

    territory_prices: dict[str, Decimal] = {}
    entry_count = 0
    for relationship in ("manualPrices", "automaticPrices"):
        payload = client.get(
            f"/v1/appPriceSchedules/{schedule_id}/{relationship}",
            {"limit": "200", "include": "appPricePoint,territory"},
        )
        entries = _collection(payload, relationship)
        links = payload.get("links")
        if isinstance(links, dict) and links.get("next"):
            raise ReleaseStatusError(f"{relationship} response unexpectedly requires paging")
        included = payload.get("included", [])
        if not isinstance(included, list):
            raise ReleaseStatusError(f"{relationship} included resources are invalid")
        price_points = {
            str(resource.get("id") or ""): _attributes(resource, "app price point").get(
                "customerPrice"
            )
            for resource in included
            if isinstance(resource, dict) and resource.get("type") == "appPricePoints"
        }
        for entry in entries:
            territory_data = _relationship_data(
                entry, "territory", "app price entry"
            )
            price_point_data = _relationship_data(
                entry, "appPricePoint", "app price entry"
            )
            territory_id = str(territory_data.get("id") or "")
            price_point_id = str(price_point_data.get("id") or "")
            if not territory_id or territory_id in territory_prices:
                raise ReleaseStatusError("app price schedule has a missing or duplicate territory")
            raw_price = price_points.get(price_point_id)
            try:
                territory_prices[territory_id] = Decimal(str(raw_price))
            except (InvalidOperation, ValueError) as exc:
                raise ReleaseStatusError("app price schedule has an invalid customer price") from exc
            entry_count += 1

    configured_territories = set(territory_prices)
    return {
        "configured": True,
        "entry_count": entry_count,
        "territory_count": len(configured_territories),
        "active_territory_count": len(active_territories),
        "all_free": all(price == 0 for price in territory_prices.values()),
        "missing_territories": sorted(active_territories - configured_territories),
        "unexpected_territories": sorted(configured_territories - active_territories),
    }


def _availability_status(
    client: AppStoreConnectClient, active_territories: set[str]
) -> dict[str, Any]:
    availability = _resource_or_none(
        client.get(
            f"/v1/apps/{APP_ID}/appAvailabilityV2",
            allow_missing_relationship=True,
        ),
        "app availability",
    )
    if availability is None:
        return {
            "configured": False,
            "available_in_new_territories": None,
            "territory_count": 0,
            "available_territory_count": 0,
            "active_territory_count": len(active_territories),
            "missing_territories": sorted(active_territories),
            "unexpected_territories": [],
        }

    availability_id = str(availability.get("id") or "")
    if not availability_id:
        raise ReleaseStatusError("app availability has no resource ID")
    availability_resource = _resource_or_none(
        client.get(f"/v2/appAvailabilities/{availability_id}"),
        "app availability detail",
    )
    if availability_resource is None:
        raise ReleaseStatusError("app availability detail is missing")
    availability_attributes = _attributes(
        availability_resource, "app availability detail"
    )
    available_in_new_territories = availability_attributes.get(
        "availableInNewTerritories"
    )
    if not isinstance(available_in_new_territories, bool):
        raise ReleaseStatusError(
            "app availability detail has no Boolean new-territory state"
        )
    payload = client.get(
        f"/v2/appAvailabilities/{availability_id}/territoryAvailabilities",
        {"limit": "200", "include": "territory"},
    )
    entries = _collection(payload, "territory availabilities")
    links = payload.get("links")
    if isinstance(links, dict) and links.get("next"):
        raise ReleaseStatusError("territory availability response unexpectedly requires paging")
    territory_availability: dict[str, bool] = {}
    for entry in entries:
        territory_data = _relationship_data(
            entry, "territory", "territory availability"
        )
        territory_id = str(territory_data.get("id") or "")
        if not territory_id or territory_id in territory_availability:
            raise ReleaseStatusError(
                "territory availability has a missing or duplicate territory"
            )
        available = _attributes(entry, "territory availability").get("available")
        if not isinstance(available, bool):
            raise ReleaseStatusError("territory availability has no Boolean state")
        territory_availability[territory_id] = available
    configured_territories = set(territory_availability)
    return {
        "configured": True,
        "available_in_new_territories": available_in_new_territories,
        "territory_count": len(configured_territories),
        "available_territory_count": sum(territory_availability.values()),
        "active_territory_count": len(active_territories),
        "missing_territories": sorted(active_territories - configured_territories),
        "unexpected_territories": sorted(configured_territories - active_territories),
    }


def _encryption_declaration_status(
    client: AppStoreConnectClient,
) -> dict[str, Any]:
    declarations = _collection(
        client.get(
            "/v1/appEncryptionDeclarations",
            {"filter[app]": APP_ID, "limit": "50"},
        ),
        "app encryption declarations",
    )
    states: list[str] = []
    for declaration in declarations:
        state = _attributes(
            declaration, "app encryption declaration"
        ).get("appEncryptionDeclarationState")
        if not isinstance(state, str) or not state:
            raise ReleaseStatusError(
                "app encryption declaration has no review state"
            )
        states.append(state)
    return {
        "count": len(declarations),
        "states": sorted(states),
        "accepted_count": sum(state == "APPROVED" for state in states),
    }


def _accessibility_declaration_status(
    client: AppStoreConnectClient,
) -> dict[str, Any]:
    declarations = _collection(
        client.get(
            f"/v1/apps/{APP_ID}/accessibilityDeclarations",
            {"limit": "50"},
        ),
        "accessibility declarations",
    )
    return {
        "count": len(declarations),
        "release_decision": "publish_no_accessibility_claims_for_build_18",
        "matches_release_decision": len(declarations) == 0,
    }


def _review_submission_status(
    client: AppStoreConnectClient,
) -> dict[str, Any]:
    submissions = _collection(
        client.get(
            f"/v1/apps/{APP_ID}/reviewSubmissions",
            {"limit": "50"},
        ),
        "review submissions",
    )
    records: list[dict[str, Any]] = []
    for submission in submissions:
        attributes = _attributes(submission, "review submission")
        platform = attributes.get("platform")
        state = attributes.get("state")
        if platform is not None and platform not in EXPECTED_PLATFORMS:
            raise ReleaseStatusError("review submission has an unexpected platform")
        if not isinstance(state, str) or not state:
            raise ReleaseStatusError("review submission has no state")
        submission_id = str(submission.get("id") or "")
        if not submission_id:
            raise ReleaseStatusError("review submission has no resource ID")
        item_payload = client.get(
            f"/v1/reviewSubmissions/{submission_id}/items",
            {
                "fields[reviewSubmissionItems]": "state,appStoreVersion",
                "fields[appStoreVersions]": "platform,versionString",
                "include": "appStoreVersion",
                "limit": "50",
            },
        )
        included_versions: dict[str, dict[str, str]] = {}
        included = item_payload.get("included", [])
        if not isinstance(included, list):
            raise ReleaseStatusError("review submission includes are malformed")
        for resource in included:
            if not isinstance(resource, dict) or resource.get("type") != "appStoreVersions":
                continue
            version_id = str(resource.get("id") or "")
            version_attributes = _attributes(resource, "review App Store version")
            version_platform = str(version_attributes.get("platform") or "")
            version_string = str(version_attributes.get("versionString") or "")
            if (
                not version_id
                or version_id in included_versions
                or version_platform not in EXPECTED_PLATFORMS
                or not version_string
            ):
                raise ReleaseStatusError("review App Store version include is malformed")
            included_versions[version_id] = {
                "platform": version_platform,
                "version": version_string,
            }
        item_resources = _collection(item_payload, "review submission items")
        item_records: list[dict[str, str]] = []
        item_platforms: set[str] = set()
        for item in item_resources:
            item_attributes = _attributes(item, "review submission item")
            item_state = item_attributes.get("state")
            if not isinstance(item_state, str) or not item_state:
                raise ReleaseStatusError("review submission item has no state")
            relationships = item.get("relationships")
            version_data: Any = None
            if isinstance(relationships, dict):
                relationship = relationships.get("appStoreVersion")
                if isinstance(relationship, dict):
                    version_data = relationship.get("data")
            if version_data is None:
                continue
            if not isinstance(version_data, dict):
                raise ReleaseStatusError(
                    "review submission item App Store version relationship is malformed"
                )
            version_id = str(version_data.get("id") or "")
            version_info = included_versions.get(version_id)
            if version_info is None:
                raise ReleaseStatusError(
                    "review submission item App Store version include is missing"
                )
            item_id = str(item.get("id") or "")
            if not item_id:
                raise ReleaseStatusError("review submission item has no resource ID")
            item_platforms.add(version_info["platform"])
            item_records.append(
                {
                    "id": item_id,
                    "state": item_state,
                    "app_store_version_id": version_id,
                    "platform": version_info["platform"],
                    "version": version_info["version"],
                }
            )
        if isinstance(platform, str):
            item_platforms.add(platform)
        records.append(
            {
                "id": submission_id,
                "platform": platform or "MULTI_PLATFORM",
                "platforms": sorted(item_platforms),
                "state": state,
                "item_count": len(item_resources),
                "non_app_store_version_item_count": (
                    len(item_resources) - len(item_records)
                ),
                "items": sorted(
                    item_records,
                    key=lambda item: (item["platform"], item["version"], item["id"]),
                ),
            }
        )
    submitted_states = {
        "WAITING_FOR_REVIEW",
        "IN_REVIEW",
        "UNRESOLVED_ISSUES",
        "COMPLETING",
        "COMPLETE",
    }
    submitted_platforms = sorted(
        {
            submitted_platform
            for record in records
            if record["state"] in submitted_states
            for submitted_platform in record["platforms"]
        }
    )
    return {
        "count": len(records),
        "records": sorted(
            records,
            key=lambda item: (item["platform"], item["state"], item["id"]),
        ),
        "submitted_platforms": submitted_platforms,
        "both_platforms_submitted": set(submitted_platforms) == {"IOS", "MAC_OS"},
    }


def set_privacy_policy_url(
    client: AppStoreConnectClient, confirm_apple_id: str
) -> None:
    if confirm_apple_id != APP_ID:
        raise ReleaseStatusError(
            f"--set-privacy-url requires --confirm-apple-id {APP_ID}"
        )
    status = _app_info_status(client)
    if status["privacy_policy_url_matches"]:
        print("PASS: App Store Connect privacy policy URL already matches")
        return
    localization_id = str(status.get("localization_id") or "")
    result = client.patch_attributes(
        f"/v1/appInfoLocalizations/{localization_id}",
        "appInfoLocalizations",
        localization_id,
        {"privacyPolicyUrl": EXPECTED_PRIVACY_URL},
    )
    resource = _resource_or_none(result, "updated app info localization")
    if resource is None:
        raise ReleaseStatusError("privacy URL update returned no resource")
    attributes = _attributes(resource, "updated app info localization")
    if attributes.get("privacyPolicyUrl") != EXPECTED_PRIVACY_URL:
        raise ReleaseStatusError("privacy URL update did not persist the expected value")
    print("PASS: App Store Connect privacy policy URL updated and verified")


def _review_contact_from_environment() -> dict[str, str]:
    values = {
        "contactFirstName": os.environ.get(
            "WINS_APPLE_REVIEW_CONTACT_FIRST_NAME", ""
        ).strip(),
        "contactLastName": os.environ.get(
            "WINS_APPLE_REVIEW_CONTACT_LAST_NAME", ""
        ).strip(),
        "contactPhone": os.environ.get("WINS_APPLE_REVIEW_CONTACT_PHONE", "").strip(),
        "contactEmail": os.environ.get("WINS_APPLE_REVIEW_CONTACT_EMAIL", "").strip(),
    }
    if not all(values.values()):
        raise ReleaseStatusError(
            "review sync requires temporary WINS_APPLE_REVIEW_CONTACT_* environment variables"
        )
    if any(len(value) > 255 for value in values.values()):
        raise ReleaseStatusError("review contact value exceeds the safety limit")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", values["contactEmail"]):
        raise ReleaseStatusError("review contact email is invalid")
    if not re.fullmatch(r"[+()0-9 .-]{7,40}", values["contactPhone"]):
        raise ReleaseStatusError("review contact phone is invalid")
    return values


def _review_notes(platform: str) -> str:
    path = (
        ROOT
        / "app_store"
        / "apple"
        / "review"
        / f"{platform}_review_notes.txt"
    )
    try:
        notes = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ReleaseStatusError(
            f"could not read {path.relative_to(ROOT)}"
        ) from exc
    if not notes or len(notes) > 4000:
        raise ReleaseStatusError(f"{path.relative_to(ROOT)} has an invalid length")
    return notes


def _editable_versions(client: AppStoreConnectClient) -> dict[str, dict[str, Any]]:
    versions = _collection(
        client.get(
            f"/v1/apps/{APP_ID}/appStoreVersions",
            {"filter[versionString]": APP_VERSION, "limit": "10"},
        ),
        "app store versions",
    )
    results: dict[str, dict[str, Any]] = {}
    for version in versions:
        attributes = _attributes(version, "app store version")
        platform = EXPECTED_PLATFORMS.get(str(attributes.get("platform") or ""))
        if platform is None or platform in results:
            raise ReleaseStatusError("unexpected App Store platform record")
        if attributes.get("appStoreState") != "PREPARE_FOR_SUBMISSION":
            raise ReleaseStatusError(
                f"{platform} {APP_VERSION} is not editable for review-detail sync"
            )
        results[platform] = version
    if set(results) != {"ios", "macos"}:
        raise ReleaseStatusError("review-detail sync requires both platform records")
    return results


def sync_review_details(
    client: AppStoreConnectClient, confirm_apple_id: str
) -> None:
    if confirm_apple_id != APP_ID:
        raise ReleaseStatusError(
            f"--sync-review-details requires --confirm-apple-id {APP_ID}"
        )
    contact = _review_contact_from_environment()
    for platform, version in _editable_versions(client).items():
        version_id = str(version.get("id") or "")
        attributes: dict[str, Any] = {
            **contact,
            "demoAccountRequired": False,
            "notes": _review_notes(platform),
        }
        existing = _resource_or_none(
            client.get(
                f"/v1/appStoreVersions/{version_id}/appStoreReviewDetail",
                allow_missing_relationship=True,
            ),
            "review detail",
        )
        if existing is None:
            result = client.post_resource(
                "/v1/appStoreReviewDetails",
                "appStoreReviewDetails",
                attributes,
                {
                    "appStoreVersion": {
                        "data": {"type": "appStoreVersions", "id": version_id}
                    }
                },
            )
        else:
            review_id = str(existing.get("id") or "")
            result = client.patch_attributes(
                f"/v1/appStoreReviewDetails/{review_id}",
                "appStoreReviewDetails",
                review_id,
                attributes,
            )
        updated = _resource_or_none(result, "updated review detail")
        if updated is None:
            raise ReleaseStatusError(f"{platform} review-detail sync returned no resource")
        updated_attributes = _attributes(updated, "updated review detail")
        if (
            updated_attributes.get("demoAccountRequired") is not False
            or not updated_attributes.get("notes")
            or any(updated_attributes.get(key) != value for key, value in contact.items())
        ):
            raise ReleaseStatusError(
                f"{platform} review-detail sync did not persist the expected fields"
            )
        print(f"PASS: {platform} App Review details updated and verified")


def sync_version_metadata(
    client: AppStoreConnectClient, confirm_apple_id: str
) -> None:
    if confirm_apple_id != APP_ID:
        raise ReleaseStatusError(
            f"--sync-version-metadata requires --confirm-apple-id {APP_ID}"
        )
    expected = {
        "description": EXPECTED_VERSION_LOCALIZATION["description"],
        "promotionalText": EXPECTED_VERSION_LOCALIZATION["promotionalText"],
    }
    for platform, version in _editable_versions(client).items():
        version_id = str(version.get("id") or "")
        localization = _version_localization(client, version_id)
        localization_id = str(localization.get("id") or "")
        if not localization_id:
            raise ReleaseStatusError(
                f"{platform} version localization has no resource ID"
            )
        result = client.patch_attributes(
            f"/v1/appStoreVersionLocalizations/{localization_id}",
            "appStoreVersionLocalizations",
            localization_id,
            expected,
        )
        updated = _resource_or_none(result, "updated version localization")
        if updated is None:
            raise ReleaseStatusError(
                f"{platform} version metadata sync returned no resource"
            )
        attributes = _attributes(updated, "updated version localization")
        if any(attributes.get(key) != value for key, value in expected.items()):
            raise ReleaseStatusError(
                f"{platform} version metadata sync did not persist the expected fields"
            )
        print(
            f"PASS: {platform} description and promotional text updated and verified"
        )


def _build_status(client: AppStoreConnectClient) -> list[dict[str, Any]]:
    payload = client.get(
        "/v1/builds",
        {
            "filter[app]": APP_ID,
            "filter[version]": BUILD_NUMBER,
            "include": "preReleaseVersion",
            "limit": "20",
        },
    )
    included = payload.get("included", [])
    prerelease_platforms: dict[str, str] = {}
    if isinstance(included, list):
        for resource in included:
            if not isinstance(resource, dict) or resource.get("type") != "preReleaseVersions":
                continue
            prerelease_platforms[str(resource.get("id") or "")] = str(
                _attributes(resource, "pre-release version").get("platform") or ""
            )

    results: list[dict[str, Any]] = []
    for build in _collection(payload, "builds"):
        attributes = _attributes(build, "build")
        relationships = build.get("relationships")
        prerelease_id = ""
        if isinstance(relationships, dict):
            prerelease = relationships.get("preReleaseVersion")
            if isinstance(prerelease, dict):
                data = prerelease.get("data")
                if isinstance(data, dict):
                    prerelease_id = str(data.get("id") or "")
        platform = prerelease_platforms.get(prerelease_id, "UNKNOWN")
        results.append(
            {
                "id": build.get("id"),
                "platform": platform,
                "version": attributes.get("version"),
                "processing_state": attributes.get("processingState"),
                "uploaded_date": attributes.get("uploadedDate"),
                "expired": attributes.get("expired"),
                "uses_non_exempt_encryption": attributes.get(
                    "usesNonExemptEncryption"
                ),
            }
        )
    return sorted(results, key=lambda item: (str(item["platform"]), str(item["id"])))


def audit(client: AppStoreConnectClient) -> dict[str, Any]:
    auth_probe.validate_app_response(
        client.get(
            "/v1/apps",
            {"filter[bundleId]": BUNDLE_ID, "limit": "1"},
        )
    )
    versions = _collection(
        client.get(
            f"/v1/apps/{APP_ID}/appStoreVersions",
            {"filter[versionString]": APP_VERSION, "limit": "10"},
        ),
        "app store versions",
    )
    if len(versions) != len(EXPECTED_PLATFORMS):
        raise ReleaseStatusError(
            f"expected two {APP_VERSION} platform records, found {len(versions)}"
        )

    platform_results: dict[str, dict[str, Any]] = {}
    for version in versions:
        version_id = str(version.get("id") or "")
        attributes = _attributes(version, "app store version")
        api_platform = str(attributes.get("platform") or "")
        platform = EXPECTED_PLATFORMS.get(api_platform)
        if platform is None or platform in platform_results:
            raise ReleaseStatusError(f"unexpected App Store platform {api_platform!r}")
        localization = _version_localization(client, version_id)
        localization_attributes = _attributes(localization, "version localization")
        mismatches = {
            key: {
                "expected": expected,
                "actual": localization_attributes.get(key),
            }
            for key, expected in EXPECTED_VERSION_LOCALIZATION.items()
            if localization_attributes.get(key) != expected
        }
        screenshot_count, screenshot_display_types = _screenshot_count(
            client, str(localization.get("id") or "")
        )
        review_detail = _resource_or_none(
            client.get(
                f"/v1/appStoreVersions/{version_id}/appStoreReviewDetail",
                allow_missing_relationship=True,
            ),
            "review detail",
        )
        review_attributes = (
            _attributes(review_detail, "review detail") if review_detail else {}
        )
        selected_build = _resource_or_none(
            client.get(
                f"/v1/appStoreVersions/{version_id}/build",
                allow_missing_relationship=True,
            ),
            "selected App Store build",
        )
        if selected_build is not None and (
            selected_build.get("type") != "builds" or not selected_build.get("id")
        ):
            raise ReleaseStatusError(
                f"{platform} selected build relationship is malformed"
            )
        platform_results[platform] = {
            "version_id": version_id,
            "state": attributes.get("appStoreState"),
            "release_type": attributes.get("releaseType"),
            "metadata_matches": not mismatches,
            "metadata_mismatches": mismatches,
            "screenshot_count": screenshot_count,
            "screenshot_display_types": screenshot_display_types,
            "review_detail_present": review_detail is not None,
            "review_contact_complete": bool(
                review_attributes.get("contactFirstName")
                and review_attributes.get("contactLastName")
                and review_attributes.get("contactPhone")
                and review_attributes.get("contactEmail")
            ),
            "demo_account_required": review_attributes.get("demoAccountRequired"),
            "review_notes_present": bool(review_attributes.get("notes")),
            "selected_build_id": (
                str(selected_build.get("id")) if selected_build is not None else None
            ),
        }

    builds = _build_status(client)
    processed_platforms = {
        EXPECTED_PLATFORMS.get(str(build.get("platform")))
        for build in builds
        if build.get("processing_state") == "VALID"
        and build.get("expired") is not True
    }
    processed_platforms.discard(None)
    app_info = _app_info_status(client)
    active_territories = _active_territory_ids(client)
    price_status = _price_status(client, active_territories)
    availability_status = _availability_status(client, active_territories)
    encryption_status = _encryption_declaration_status(client)
    accessibility_status = _accessibility_declaration_status(client)
    review_submission_status = _review_submission_status(client)
    return {
        "schema_version": 1,
        "app_id": APP_ID,
        "bundle_id": BUNDLE_ID,
        "app_version": APP_VERSION,
        "build_number": BUILD_NUMBER,
        "platforms": platform_results,
        "builds": builds,
        "processed_platforms": sorted(processed_platforms),
        "both_platform_builds_processed": processed_platforms == {"ios", "macos"},
        "app_info": app_info,
        "price_schedule": price_status,
        "availability": availability_status,
        "encryption_declarations": encryption_status,
        "accessibility_declarations": accessibility_status,
        "review_submissions": review_submission_status,
    }


def _print_human(result: dict[str, Any]) -> None:
    print(f"PASS: universal app record matched Apple ID {APP_ID} / {BUNDLE_ID}")
    platforms = result["platforms"]
    for platform in ("ios", "macos"):
        item = platforms[platform]
        print(
            f"PASS: {platform} {APP_VERSION} record state={item['state']} "
            f"release={item['release_type']}"
        )
        marker = "PASS" if item["metadata_matches"] else "WARN"
        print(f"{marker}: {platform} en-US metadata matches local release files")
        marker = "PASS" if item["screenshot_count"] > 0 else "PENDING"
        print(
            f"{marker}: {platform} screenshots uploaded={item['screenshot_count']}"
        )
        marker = "PASS" if item["review_contact_complete"] else "PENDING"
        print(f"{marker}: {platform} App Review contact and notes configured")
        marker = "PASS" if item["selected_build_id"] else "PENDING"
        print(
            f"{marker}: {platform} selected build="
            f"{item['selected_build_id'] or 'none'}"
        )
    app_info = result["app_info"]
    marker = "PASS" if app_info["privacy_policy_url_matches"] else "PENDING"
    print(
        f"{marker}: privacy policy URL "
        f"{app_info['privacy_policy_url'] or 'not configured'}"
    )
    price_status = result["price_schedule"]
    price_ready = (
        price_status["configured"]
        and price_status["all_free"]
        and not price_status["missing_territories"]
        and not price_status["unexpected_territories"]
        and price_status["territory_count"] == price_status["active_territory_count"]
    )
    marker = "PASS" if price_ready else "PENDING"
    print(
        f"{marker}: free price schedule storefronts="
        f"{price_status['territory_count']}/{price_status['active_territory_count']}"
    )
    availability = result["availability"]
    availability_ready = (
        availability["configured"]
        and not availability["missing_territories"]
        and not availability["unexpected_territories"]
        and availability["available_territory_count"]
        == availability["active_territory_count"]
    )
    marker = "PASS" if availability_ready else "PENDING"
    print(
        f"{marker}: storefront availability configured={availability['configured']} "
        f"available={availability['available_territory_count']}/"
        f"{availability['active_territory_count']}"
    )
    encryption = result["encryption_declarations"]
    marker = "PASS" if encryption["accepted_count"] > 0 else "PENDING"
    print(
        f"{marker}: accepted encryption declarations="
        f"{encryption['accepted_count']}/{encryption['count']}"
    )
    accessibility = result["accessibility_declarations"]
    marker = "PASS" if accessibility["matches_release_decision"] else "WARN"
    print(
        f"{marker}: accessibility declarations published="
        f"{accessibility['count']} decision=no claims for build 18"
    )
    review_submissions = result["review_submissions"]
    marker = "PASS" if review_submissions["both_platforms_submitted"] else "PENDING"
    print(
        f"{marker}: App Review submissions={review_submissions['count']} "
        f"submitted_platforms="
        f"{','.join(review_submissions['submitted_platforms']) or 'none'}"
    )
    if result["builds"]:
        for build in result["builds"]:
            print(
                "BUILD: "
                f"platform={build['platform']} number={build['version']} "
                f"state={build['processing_state']} expired={build['expired']}"
            )
    else:
        print(f"PENDING: build {BUILD_NUMBER} is not uploaded")
    print(
        "SUMMARY: "
        f"processed_platforms={','.join(result['processed_platforms']) or 'none'}; "
        f"both_processed={result['both_platform_builds_processed']}"
    )


def run_selftest() -> None:
    resources = _collection({"data": [{"id": "one"}]}, "test")
    if _exactly_one(resources, "test")["id"] != "one":
        raise ReleaseStatusError("self-test could not read a single resource")
    for payload in ({}, {"data": {}}, {"data": ["bad"]}):
        try:
            _collection(payload, "test")
        except ReleaseStatusError:
            continue
        raise ReleaseStatusError("self-test accepted an invalid collection")
    try:
        _exactly_one([], "test")
    except ReleaseStatusError:
        pass
    else:
        raise ReleaseStatusError("self-test accepted an empty single-resource list")
    relationship = _relationship_data(
        {"relationships": {"item": {"data": {"id": "one"}}}},
        "item",
        "test",
    )
    if relationship.get("id") != "one":
        raise ReleaseStatusError("self-test could not read relationship data")
    for resource in ({}, {"relationships": {}}, {"relationships": {"item": {}}}):
        try:
            _relationship_data(resource, "item", "test")
        except ReleaseStatusError:
            continue
        raise ReleaseStatusError("self-test accepted malformed relationship data")

    class CrossPlatformReviewClient:
        def get(
            self,
            path: str,
            _params: dict[str, str] | None = None,
        ) -> dict[str, Any]:
            if path == f"/v1/apps/{APP_ID}/reviewSubmissions":
                return {
                    "data": [
                        {
                            "type": "reviewSubmissions",
                            "id": "submission-one",
                            "attributes": {"state": "WAITING_FOR_REVIEW"},
                        }
                    ]
                }
            if path == "/v1/reviewSubmissions/submission-one/items":
                return {
                    "data": [
                        {
                            "type": "reviewSubmissionItems",
                            "id": "item-ios",
                            "attributes": {"state": "ACCEPTED"},
                            "relationships": {
                                "appStoreVersion": {
                                    "data": {
                                        "type": "appStoreVersions",
                                        "id": "version-ios",
                                    }
                                }
                            },
                        },
                        {
                            "type": "reviewSubmissionItems",
                            "id": "item-macos",
                            "attributes": {"state": "ACCEPTED"},
                            "relationships": {
                                "appStoreVersion": {
                                    "data": {
                                        "type": "appStoreVersions",
                                        "id": "version-macos",
                                    }
                                }
                            },
                        },
                    ],
                    "included": [
                        {
                            "type": "appStoreVersions",
                            "id": "version-ios",
                            "attributes": {
                                "platform": "IOS",
                                "versionString": APP_VERSION,
                            },
                        },
                        {
                            "type": "appStoreVersions",
                            "id": "version-macos",
                            "attributes": {
                                "platform": "MAC_OS",
                                "versionString": APP_VERSION,
                            },
                        },
                    ],
                }
            raise ReleaseStatusError(f"self-test received unexpected path {path}")

    review_status = _review_submission_status(CrossPlatformReviewClient())
    if (
        review_status["submitted_platforms"] != ["IOS", "MAC_OS"]
        or review_status["both_platforms_submitted"] is not True
        or review_status["records"][0]["platform"] != "MULTI_PLATFORM"
        or review_status["records"][0]["item_count"] != 2
        or review_status["records"][0]["non_app_store_version_item_count"] != 0
    ):
        raise ReleaseStatusError(
            "self-test did not infer a cross-platform review submission"
        )
    print("PASS: App Store Connect release status self-test")
    print("SUMMARY: 1/1 checks passing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--set-privacy-url", action="store_true")
    parser.add_argument("--sync-review-details", action="store_true")
    parser.add_argument("--sync-version-metadata", action="store_true")
    parser.add_argument("--confirm-apple-id", default="")
    args = parser.parse_args()
    try:
        if args.selftest:
            run_selftest()
            return 0
        client = _load_client()
        if args.set_privacy_url:
            set_privacy_policy_url(client, args.confirm_apple_id)
        if args.sync_review_details:
            sync_review_details(client, args.confirm_apple_id)
        if args.sync_version_metadata:
            sync_version_metadata(client, args.confirm_apple_id)
        if not (
            args.set_privacy_url
            or args.sync_review_details
            or args.sync_version_metadata
        ) and args.confirm_apple_id:
            raise ReleaseStatusError(
                "--confirm-apple-id requires a guarded mutation action"
            )
        result = audit(client)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            _print_human(result)
    except (ReleaseStatusError, auth_probe.ProbeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
