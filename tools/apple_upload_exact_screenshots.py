#!/usr/bin/env python3
"""Upload only the hash-pinned Apple screenshots after every owner gate passes."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import apple_app_store_connect_auth_probe as auth_probe
from apple_app_store_connect_release_status import (
    APP_ID,
    AppStoreConnectClient,
    ReleaseStatusError,
    _attributes,
    _collection,
    _editable_versions,
    _load_client,
    _resource_or_none,
    _version_localization,
)
from validate_apple_owner_signoff import validate_owner_signoff


ROOT = Path(__file__).resolve().parents[1]
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
UPLOAD_TIMEOUT_SECONDS = 60
UPLOAD_SUCCESS_STATUS = 200
MAX_UPLOAD_URL_BYTES = 8192
MAX_UPLOAD_RESPONSE_BYTES = 64 * 1024
UPLOAD_READ_CHUNK_BYTES = 16 * 1024
MAX_UPLOAD_RESPONSE_HEADERS = 64
MAX_UPLOAD_RESPONSE_HEADER_BYTES = 32 * 1024
MAX_OPERATION_HEADERS = 32
MAX_OPERATION_HEADER_BYTES = 16 * 1024
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_BAD_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_FORBIDDEN_OPERATION_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class ScreenshotUploadError(RuntimeError):
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
            "screenshot upload redirect refused",
            headers,
            fp,
        )


_UPLOAD_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirectHandler(),
)


@dataclass(frozen=True)
class ScreenshotCandidate:
    platform: str
    path: Path
    sha256: str
    width: int
    height: int
    display_type: str


CANDIDATES = {
    "ios": ScreenshotCandidate(
        platform="ios",
        path=ROOT / "app_store/apple/screenshots/candidates/ios-6_9/01-main.png",
        sha256="b3c5150e0baccb681a3b54d63a7f0a580fcc9881637ac55d174a7cf166d05db1",
        width=1320,
        height=2868,
        display_type="APP_IPHONE_67",
    ),
    "macos": ScreenshotCandidate(
        platform="macos",
        path=ROOT / "app_store/apple/screenshots/candidates/macos-16_10/01-main.png",
        sha256="a9645a95e89fd0e86806bffdba391502d971d65ac932f9034b80d2747aad03e1",
        width=2560,
        height=1600,
        display_type="APP_DESKTOP",
    ),
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def png_dimensions(path: Path) -> tuple[int, int]:
    try:
        with path.open("rb") as handle:
            header = handle.read(24)
    except OSError as exc:
        raise ScreenshotUploadError("screenshot candidate is not readable") from exc
    if (
        len(header) != 24
        or header[:8] != PNG_MAGIC
        or header[12:16] != b"IHDR"
    ):
        raise ScreenshotUploadError("screenshot candidate is not a valid PNG")
    return struct.unpack(">II", header[16:24])


def verify_candidate(candidate: ScreenshotCandidate) -> None:
    try:
        resolved = candidate.path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ScreenshotUploadError(
            f"{candidate.platform} screenshot is missing or outside the project"
        ) from exc
    if candidate.path.is_symlink() or not resolved.is_file():
        raise ScreenshotUploadError(
            f"{candidate.platform} screenshot must be a regular non-symlink file"
        )
    if png_dimensions(resolved) != (candidate.width, candidate.height):
        raise ScreenshotUploadError(
            f"{candidate.platform} screenshot dimensions changed"
        )
    if file_sha256(resolved) != candidate.sha256:
        raise ScreenshotUploadError(f"{candidate.platform} screenshot hash changed")


def require_confirmation(label: str, supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise ScreenshotUploadError(
            f"{label} confirmation does not match the frozen screenshot"
        )


def run_submission_gate() -> None:
    completed = subprocess.run(
        # Release-ready mode: the plain validator requires the pre-release-ready
        # records that the --require-approved owner sign-off below refuses.
        [sys.executable, "tools/validate_apple_submission_package.py", "--release-ready"],
        cwd=ROOT,
        check=False,
    )
    if completed.returncode != 0:
        raise ScreenshotUploadError("Apple submission package validation failed")
    try:
        validate_owner_signoff(ROOT, require_approved=True)
    except AssertionError as exc:
        raise ScreenshotUploadError(str(exc)) from exc


def localization_ids(client: AppStoreConnectClient) -> dict[str, str]:
    results: dict[str, str] = {}
    for platform, version in _editable_versions(client).items():
        version_id = str(version.get("id") or "")
        localization = _version_localization(client, version_id)
        localization_id = str(localization.get("id") or "")
        if not localization_id:
            raise ScreenshotUploadError(
                f"{platform} App Store localization has no resource ID"
            )
        results[platform] = localization_id
    return results


def target_set_state(
    client: AppStoreConnectClient,
    localization_id: str,
    display_type: str,
) -> tuple[str | None, list[str]]:
    sets = _collection(
        client.get(
            f"/v1/appStoreVersionLocalizations/{localization_id}/appScreenshotSets",
            {"limit": "50"},
        ),
        "app screenshot sets",
    )
    matching: list[str] = []
    matching_screenshot_ids: list[str] = []
    unexpected_screenshot_count = 0
    for screenshot_set in sets:
        screenshot_set_id = str(screenshot_set.get("id") or "")
        if not screenshot_set_id:
            raise ScreenshotUploadError("App Store screenshot set has no resource ID")
        is_target = (
            _attributes(screenshot_set, "app screenshot set").get(
                "screenshotDisplayType"
            )
            == display_type
        )
        if is_target:
            matching.append(screenshot_set_id)
        screenshots = _collection(
            client.get(
                f"/v1/appScreenshotSets/{screenshot_set_id}/appScreenshots",
                {"limit": "200"},
            ),
            "app screenshots",
        )
        if is_target:
            for screenshot in screenshots:
                screenshot_id = str(screenshot.get("id") or "")
                if not screenshot_id:
                    raise ScreenshotUploadError(
                        "App Store screenshot has no resource ID"
                    )
                matching_screenshot_ids.append(screenshot_id)
        else:
            unexpected_screenshot_count += len(screenshots)
    if len(matching) > 1:
        raise ScreenshotUploadError("App Store has duplicate target screenshot sets")
    if unexpected_screenshot_count:
        raise ScreenshotUploadError(
            "App Store contains screenshots outside the frozen target set"
        )
    return (matching[0] if matching else None, matching_screenshot_ids)


def create_screenshot_set(
    client: AppStoreConnectClient,
    localization_id: str,
    display_type: str,
) -> str:
    result = client.post_resource(
        "/v1/appScreenshotSets",
        "appScreenshotSets",
        {"screenshotDisplayType": display_type},
        {
            "appStoreVersionLocalization": {
                "data": {
                    "type": "appStoreVersionLocalizations",
                    "id": localization_id,
                }
            }
        },
    )
    resource = _resource_or_none(result, "created screenshot set")
    screenshot_set_id = str(resource.get("id") if resource else "")
    if not screenshot_set_id:
        raise ScreenshotUploadError("created screenshot set has no resource ID")
    return screenshot_set_id


def create_reservation(
    client: AppStoreConnectClient,
    screenshot_set_id: str,
    candidate: ScreenshotCandidate,
) -> dict[str, Any]:
    result = client.post_resource(
        "/v1/appScreenshots",
        "appScreenshots",
        {"fileName": candidate.path.name, "fileSize": candidate.path.stat().st_size},
        {
            "appScreenshotSet": {
                "data": {"type": "appScreenshotSets", "id": screenshot_set_id}
            }
        },
    )
    resource = _resource_or_none(result, "created screenshot reservation")
    if resource is None or not resource.get("id"):
        raise ScreenshotUploadError("screenshot reservation has no resource ID")
    return resource


def _validate_upload_url(url: str) -> str:
    try:
        encoded_url = url.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ScreenshotUploadError(
            "Apple returned an unsafe screenshot upload URL"
        ) from exc
    if (
        not encoded_url
        or len(encoded_url) > MAX_UPLOAD_URL_BYTES
        or any(byte <= 0x20 or byte == 0x7F for byte in encoded_url)
        or b"\\" in encoded_url
        or _BAD_PERCENT_ESCAPE_RE.search(url)
    ):
        raise ScreenshotUploadError("Apple returned an unsafe screenshot upload URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise ScreenshotUploadError(
            "Apple returned an unsafe screenshot upload URL"
        ) from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.path.startswith("/")
        or parsed.fragment
        or hostname.endswith(".")
        or hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
    ):
        raise ScreenshotUploadError("Apple returned an unsafe screenshot upload URL")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ScreenshotUploadError(
            "Apple returned an unsafe screenshot upload URL"
        ) from exc
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname:
            raise ScreenshotUploadError(
                "Apple returned an unsafe screenshot upload URL"
            )
    else:
        if not address.is_global:
            raise ScreenshotUploadError(
                "Apple returned a non-public screenshot upload address"
            )
    return url


def _validated_operation_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, list) or len(headers) > MAX_OPERATION_HEADERS:
        raise ScreenshotUploadError("Apple returned invalid upload headers")
    safe_headers: dict[str, str] = {}
    seen_names: set[str] = set()
    total_bytes = 0
    for header in headers:
        if not isinstance(header, dict):
            raise ScreenshotUploadError("Apple returned a malformed upload header")
        name = header.get("name")
        value = header.get("value")
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name
            or not _HEADER_NAME_RE.fullmatch(name)
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        ):
            raise ScreenshotUploadError("Apple returned an invalid upload header")
        normalized_name = name.lower()
        if (
            normalized_name in _FORBIDDEN_OPERATION_HEADERS
            or normalized_name in seen_names
        ):
            raise ScreenshotUploadError("Apple returned a forbidden upload header")
        try:
            header_bytes = len(name.encode("ascii")) + len(value.encode("latin-1"))
        except UnicodeEncodeError as exc:
            raise ScreenshotUploadError(
                "Apple returned an invalid upload header"
            ) from exc
        total_bytes += header_bytes
        if total_bytes > MAX_OPERATION_HEADER_BYTES:
            raise ScreenshotUploadError("Apple returned oversized upload headers")
        seen_names.add(normalized_name)
        safe_headers[name] = value
    return safe_headers


def _validate_response_headers(headers: Any) -> None:
    try:
        items = list(headers.items())
    except (AttributeError, TypeError, ValueError) as exc:
        raise ScreenshotUploadError(
            "screenshot part upload returned malformed headers"
        ) from exc
    if len(items) > MAX_UPLOAD_RESPONSE_HEADERS:
        raise ScreenshotUploadError(
            "screenshot part upload returned oversized headers"
        )
    total_bytes = 0
    seen_names: set[str] = set()
    for name, value in items:
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not _HEADER_NAME_RE.fullmatch(name)
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
            or name.lower() in seen_names
        ):
            raise ScreenshotUploadError(
                "screenshot part upload returned malformed headers"
            )
        try:
            total_bytes += len(name.encode("ascii")) + len(value.encode("latin-1"))
        except UnicodeEncodeError as exc:
            raise ScreenshotUploadError(
                "screenshot part upload returned malformed headers"
            ) from exc
        if total_bytes > MAX_UPLOAD_RESPONSE_HEADER_BYTES:
            raise ScreenshotUploadError(
                "screenshot part upload returned oversized headers"
            )
        seen_names.add(name.lower())


def _read_bounded_response(response: Any) -> bytes:
    headers = getattr(response, "headers", None)
    try:
        content_length = headers.get("Content-Length")
    except (AttributeError, TypeError, ValueError) as exc:
        raise ScreenshotUploadError(
            "screenshot part upload returned malformed headers"
        ) from exc
    declared_length: int | None = None
    if content_length is not None:
        if (
            not isinstance(content_length, str)
            or re.fullmatch(r"0|[1-9][0-9]*", content_length) is None
        ):
            raise ScreenshotUploadError(
                "screenshot part upload returned invalid Content-Length"
            )
        declared_length = int(content_length, 10)
        if declared_length < 0 or declared_length > MAX_UPLOAD_RESPONSE_BYTES:
            raise ScreenshotUploadError(
                "screenshot part upload response exceeded the safety limit"
            )
    chunks: list[bytes] = []
    total_bytes = 0
    while True:
        chunk = response.read(
            min(
                UPLOAD_READ_CHUNK_BYTES,
                MAX_UPLOAD_RESPONSE_BYTES + 1 - total_bytes,
            )
        )
        if not isinstance(chunk, bytes):
            raise ScreenshotUploadError(
                "screenshot part upload returned non-byte response data"
            )
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_UPLOAD_RESPONSE_BYTES:
            raise ScreenshotUploadError(
                "screenshot part upload response exceeded the safety limit"
            )
        chunks.append(chunk)
    body = b"".join(chunks)
    if declared_length is not None and declared_length != total_bytes:
        raise ScreenshotUploadError(
            "screenshot part upload response length did not match Content-Length"
        )
    return body


def validated_upload_operations(
    resource: dict[str, Any], file_size: int
) -> list[dict[str, Any]]:
    operations = _attributes(resource, "screenshot reservation").get(
        "uploadOperations"
    )
    if not isinstance(operations, list) or not operations:
        raise ScreenshotUploadError("Apple returned no screenshot upload operations")
    validated: list[dict[str, Any]] = []
    for operation in operations:
        if not isinstance(operation, dict):
            raise ScreenshotUploadError("Apple returned a malformed upload operation")
        method = operation.get("method")
        url = operation.get("url")
        offset = operation.get("offset")
        length = operation.get("length")
        headers = operation.get("requestHeaders")
        if method != "PUT" or not isinstance(url, str):
            raise ScreenshotUploadError("Apple returned an unsupported upload operation")
        _validate_upload_url(url)
        if type(offset) is not int or type(length) is not int or length <= 0:
            raise ScreenshotUploadError("Apple returned an invalid upload byte range")
        safe_headers = _validated_operation_headers(headers)
        validated.append(
            {
                "method": method,
                "url": url,
                "offset": offset,
                "length": length,
                "headers": safe_headers,
            }
        )
    validated.sort(key=lambda item: item["offset"])
    expected_offset = 0
    for operation in validated:
        if operation["offset"] != expected_offset:
            raise ScreenshotUploadError("Apple upload operations have a gap or overlap")
        expected_offset += operation["length"]
    if expected_offset != file_size:
        raise ScreenshotUploadError("Apple upload operations do not cover the exact file")
    return validated


def _upload_part(
    operation: dict[str, Any],
    part: bytes,
    opener: Any = None,
) -> None:
    method = operation.get("method")
    url = operation.get("url")
    length = operation.get("length")
    headers = operation.get("headers")
    if method != "PUT" or not isinstance(url, str):
        raise ScreenshotUploadError("invalid validated screenshot upload operation")
    expected_url = _validate_upload_url(url)
    if type(length) is not int or length <= 0 or len(part) != length:
        raise ScreenshotUploadError("screenshot upload part length changed")
    if not isinstance(headers, dict):
        raise ScreenshotUploadError("screenshot upload headers changed")
    safe_headers = _validated_operation_headers(
        [{"name": name, "value": value} for name, value in headers.items()]
    )
    request = urllib.request.Request(
        expected_url,
        method=method,
        data=part,
        headers=safe_headers,
    )
    if (
        request.full_url != expected_url
        or request.get_method() != method
        or request.data != part
    ):
        raise ScreenshotUploadError("screenshot upload request identity changed")
    selected_opener = _UPLOAD_OPENER if opener is None else opener
    try:
        with selected_opener.open(
            request,
            timeout=UPLOAD_TIMEOUT_SECONDS,
        ) as response:
            try:
                response_url = response.geturl()
            except (AttributeError, TypeError, ValueError) as exc:
                raise ScreenshotUploadError(
                    "screenshot part upload returned a malformed response"
                ) from exc
            if response_url != expected_url:
                raise ScreenshotUploadError(
                    "screenshot part upload response URL changed"
                )
            status = getattr(response, "status", None)
            if type(status) is not int:
                raise ScreenshotUploadError(
                    "screenshot part upload returned a malformed status"
                )
            _validate_response_headers(getattr(response, "headers", None))
            _read_bounded_response(response)
            if status != UPLOAD_SUCCESS_STATUS:
                if 300 <= status < 400:
                    raise ScreenshotUploadError(
                        f"screenshot part upload redirect refused: HTTP {status}"
                    )
                raise ScreenshotUploadError(
                    f"screenshot part upload returned HTTP {status}"
                )
    except urllib.error.HTTPError as exc:
        try:
            try:
                error_url = exc.geturl()
            except (AttributeError, TypeError, ValueError) as url_exc:
                raise ScreenshotUploadError(
                    "screenshot part upload returned a malformed error"
                ) from url_exc
            if error_url != expected_url:
                raise ScreenshotUploadError(
                    "screenshot part upload error URL changed"
                )
            _validate_response_headers(getattr(exc, "headers", None))
            _read_bounded_response(exc)
            if type(exc.code) is not int:
                raise ScreenshotUploadError(
                    "screenshot part upload returned a malformed error status"
                )
            if 300 <= exc.code < 400:
                raise ScreenshotUploadError(
                    f"screenshot part upload redirect refused: HTTP {exc.code}"
                )
            raise ScreenshotUploadError(
                f"screenshot part upload returned HTTP {exc.code}"
            )
        finally:
            exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ScreenshotUploadError("screenshot part upload failed") from exc


def upload_parts(path: Path, operations: list[dict[str, Any]]) -> None:
    data = path.read_bytes()
    for operation in operations:
        offset = operation["offset"]
        length = operation["length"]
        _upload_part(operation, data[offset : offset + length])


def md5_checksum(path: Path) -> str:
    try:
        digest = hashlib.md5(usedforsecurity=False)
    except TypeError:
        digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_for_complete(
    client: AppStoreConnectClient,
    screenshot_id: str,
    candidate: ScreenshotCandidate,
    timeout_seconds: int = 180,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        resource = _resource_or_none(
            client.get(f"/v1/appScreenshots/{screenshot_id}"),
            "uploaded screenshot",
        )
        if resource is None:
            raise ScreenshotUploadError("uploaded screenshot disappeared during processing")
        attributes = _attributes(resource, "uploaded screenshot")
        delivery = attributes.get("assetDeliveryState")
        if not isinstance(delivery, dict):
            raise ScreenshotUploadError("uploaded screenshot has no delivery state")
        state = delivery.get("state")
        if state == "COMPLETE":
            image_asset = attributes.get("imageAsset")
            if isinstance(image_asset, dict):
                width = image_asset.get("width")
                height = image_asset.get("height")
                if width is not None and height is not None and (
                    width,
                    height,
                ) != (candidate.width, candidate.height):
                    raise ScreenshotUploadError(
                        "Apple processed screenshot dimensions do not match"
                    )
            return
        if state == "FAILED":
            raise ScreenshotUploadError("Apple screenshot processing failed")
        if state not in {"AWAITING_UPLOAD", "UPLOAD_COMPLETE"}:
            raise ScreenshotUploadError("Apple returned an unknown screenshot state")
        time.sleep(2)
    raise ScreenshotUploadError("Apple screenshot processing timed out")


def cleanup_created_resources(
    client: AppStoreConnectClient,
    screenshot_id: str | None,
    screenshot_set_id: str | None,
) -> None:
    if screenshot_id:
        try:
            client.delete_resource(
                f"/v1/appScreenshots/{screenshot_id}",
                "appScreenshots",
                screenshot_id,
            )
        except ReleaseStatusError:
            print("WARN: could not remove failed screenshot reservation", file=sys.stderr)
    if screenshot_set_id:
        try:
            client.delete_resource(
                f"/v1/appScreenshotSets/{screenshot_set_id}",
                "appScreenshotSets",
                screenshot_set_id,
            )
        except ReleaseStatusError:
            print("WARN: could not remove empty screenshot set", file=sys.stderr)


def upload_candidate(
    client: AppStoreConnectClient,
    localization_id: str,
    candidate: ScreenshotCandidate,
    existing_set_id: str | None,
) -> str:
    created_set_id: str | None = None
    screenshot_id: str | None = None
    try:
        screenshot_set_id = existing_set_id
        if screenshot_set_id is None:
            screenshot_set_id = create_screenshot_set(
                client, localization_id, candidate.display_type
            )
            created_set_id = screenshot_set_id
        reservation = create_reservation(client, screenshot_set_id, candidate)
        screenshot_id = str(reservation.get("id") or "")
        operations = validated_upload_operations(
            reservation, candidate.path.stat().st_size
        )
        upload_parts(candidate.path, operations)
        client.patch_attributes(
            f"/v1/appScreenshots/{screenshot_id}",
            "appScreenshots",
            screenshot_id,
            {
                "uploaded": True,
                "sourceFileChecksum": md5_checksum(candidate.path),
            },
        )
        wait_for_complete(client, screenshot_id, candidate)
    except Exception:
        cleanup_created_resources(client, screenshot_id, created_set_id)
        raise
    print(
        f"PASS: Apple processed exact {candidate.platform} screenshot "
        f"sha256={candidate.sha256}"
    )
    return screenshot_id


def remove_superseded_screenshots(
    client: AppStoreConnectClient,
    screenshot_ids: list[str],
) -> None:
    for screenshot_id in screenshot_ids:
        client.delete_resource(
            f"/v1/appScreenshots/{screenshot_id}",
            "appScreenshots",
            screenshot_id,
        )
    if screenshot_ids:
        print(
            f"PASS: removed {len(screenshot_ids)} superseded App Store screenshot(s)"
        )


def selected_platforms(value: str) -> list[str]:
    return ["ios", "macos"] if value == "both" else [value]


def validate_target_screenshot_count(
    platform: str,
    existing_ids: list[str],
    replace_existing: bool,
) -> None:
    if replace_existing:
        if len(existing_ids) != 1:
            raise ScreenshotUploadError(
                f"{platform} replacement requires exactly one existing screenshot"
            )
    elif existing_ids:
        raise ScreenshotUploadError(
            "App Store already contains screenshots; pass --replace-existing "
            "only for an owner-approved replacement"
        )


def run_selftest() -> None:
    operations = validated_upload_operations(
        {
            "attributes": {
                "uploadOperations": [
                    {
                        "method": "PUT",
                        "url": "https://store-001.blobstore.apple.com/upload?token=test",
                        "offset": 0,
                        "length": 4,
                        "requestHeaders": [
                            {"name": "Content-Type", "value": "image/png"}
                        ],
                    },
                    {
                        "method": "PUT",
                        "url": "https://store-001.blobstore.apple.com/upload?token=test2",
                        "offset": 4,
                        "length": 6,
                        "requestHeaders": [],
                    },
                ]
            }
        },
        10,
    )
    if len(operations) != 2:
        raise ScreenshotUploadError("self-test lost a valid upload operation")
    for bad_url in (
        "http://store-001.blobstore.apple.com/upload",
        "https://127.0.0.1/upload",
        "https://localhost/upload",
    ):
        try:
            validated_upload_operations(
                {
                    "attributes": {
                        "uploadOperations": [
                            {
                                "method": "PUT",
                                "url": bad_url,
                                "offset": 0,
                                "length": 10,
                                "requestHeaders": [],
                            }
                        ]
                    }
                },
                10,
            )
        except ScreenshotUploadError:
            continue
        raise ScreenshotUploadError("self-test accepted an unsafe upload URL")
    try:
        validated_upload_operations(
            {
                "attributes": {
                    "uploadOperations": [
                        {
                            "method": "PUT",
                            "url": "https://store-001.blobstore.apple.com/upload",
                            "offset": 1,
                            "length": 9,
                            "requestHeaders": [],
                        }
                    ]
                }
            },
            10,
        )
    except ScreenshotUploadError:
        pass
    else:
        raise ScreenshotUploadError("self-test accepted an incomplete byte range")
    validate_target_screenshot_count("ios", [], False)
    validate_target_screenshot_count("ios", ["old-screenshot"], True)
    for existing_ids, replace_existing in (
        (["old-screenshot"], False),
        ([], True),
        (["old-1", "old-2"], True),
    ):
        try:
            validate_target_screenshot_count(
                "ios", existing_ids, replace_existing
            )
        except ScreenshotUploadError:
            continue
        raise ScreenshotUploadError(
            "self-test accepted an ambiguous screenshot replacement state"
        )
    print("PASS: exact Apple screenshot uploader self-test")
    print("SUMMARY: 1/1 checks passing")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("both", "ios", "macos"), default="both")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help=(
            "replace one existing screenshot per selected platform only after "
            "Apple finishes processing the frozen replacement"
        ),
    )
    parser.add_argument("--confirm-apple-id")
    parser.add_argument("--confirm-ios-sha256")
    parser.add_argument("--confirm-macos-sha256")
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            if args.preflight or args.upload or args.replace_existing:
                raise ScreenshotUploadError(
                    "--selftest cannot be combined with release actions"
                )
            run_selftest()
            return 0
        platforms = selected_platforms(args.platform)
        for platform in platforms:
            candidate = CANDIDATES[platform]
            verify_candidate(candidate)
            print(
                f"PASS: frozen {platform} screenshot verified "
                f"sha256={candidate.sha256} dimensions="
                f"{candidate.width}x{candidate.height}"
            )
        if not args.preflight and not args.upload:
            if args.replace_existing:
                raise ScreenshotUploadError(
                    "--replace-existing requires --preflight or --upload"
                )
            print("DRY RUN: no App Store screenshot record or upload was created")
            return 0

        require_confirmation("Apple ID", args.confirm_apple_id, APP_ID)
        if "ios" in platforms:
            require_confirmation(
                "iOS screenshot SHA-256",
                args.confirm_ios_sha256,
                CANDIDATES["ios"].sha256,
            )
        if "macos" in platforms:
            require_confirmation(
                "macOS screenshot SHA-256",
                args.confirm_macos_sha256,
                CANDIDATES["macos"].sha256,
            )
        run_submission_gate()
        auth_probe.probe()
        client = _load_client()
        localizations = localization_ids(client)
        target_states = {
            platform: target_set_state(
                client,
                localizations[platform],
                CANDIDATES[platform].display_type,
            )
            for platform in platforms
        }
        for platform, (_, existing_ids) in target_states.items():
            validate_target_screenshot_count(
                platform, existing_ids, args.replace_existing
            )
        print("PASS: owner, package, authentication, and target-set gates passed")
        if not args.upload:
            print("PREFLIGHT ONLY: no screenshot record or upload was created")
            return 0
        for platform in platforms:
            existing_set_id, existing_ids = target_states[platform]
            upload_candidate(
                client,
                localizations[platform],
                CANDIDATES[platform],
                existing_set_id,
            )
            if args.replace_existing:
                remove_superseded_screenshots(client, existing_ids)
        return 0
    except (
        ScreenshotUploadError,
        ReleaseStatusError,
        auth_probe.ProbeError,
        AssertionError,
        OSError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
