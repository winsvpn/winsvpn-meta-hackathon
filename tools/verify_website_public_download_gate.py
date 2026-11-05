#!/usr/bin/env python3
"""Final local gate for the public website download surface.

This gate composes the exact-byte custody verifier with the deployable website
sources. A safe all-pending website is BLOCKED, never release-ready. READY is
reserved for a complete current signed release whose local artifact custody
passes and whose public links expose only manifest-bound destinations.
"""

from __future__ import annotations

import importlib.util
import json
import re
import stat
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent
WEB_RELATIVE = Path("web")
MANIFEST_RELATIVE = WEB_RELATIVE / "releases" / "downloads.json"
DOWNLOADS_RELATIVE = WEB_RELATIVE / "downloads"
WORKER_RELATIVE = WEB_RELATIVE / "_worker.js"
REDIRECTS_RELATIVE = WEB_RELATIVE / "_redirects"
ASSETSIGNORE_RELATIVE = WEB_RELATIVE / ".assetsignore"
NETLIFY_FUNCTIONS_RELATIVE = Path("netlify") / "functions"

STATUS_READY = "ready"
STATUS_BLOCKED = "blocked"
STATUS_FAILED = "failed"
EXIT_READY = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 78

PENDING_STATUS = "verification_pending"
STORE_PENDING_STATUS = "store_pending"
AVAILABLE_STATUS = "available"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
PUBLIC_SOURCE_SUFFIXES = frozenset({".html", ".js", ".json", ".txt"})
PLATFORM_ALIASES = {
    "windows": ("windows",),
    "android": ("android",),
    "linux": ("linux",),
    "macos": ("macos", "mac os", "macbook"),
    "ios": ("ios", "iphone"),
}
REQUIRED_SUPPORT_SOURCES = (
    WEB_RELATIVE / "_worker.js",
    NETLIFY_FUNCTIONS_RELATIVE / "wins-ai-chat.js",
)
RELEASE_AUTHORITY_MARKER = "The Download menu is the release authority"
PENDING_MARKER = "verification pending"


class PublicDownloadGateError(RuntimeError):
    """A local source could not be evaluated without weakening the gate."""


class GateReport:
    def __init__(
        self,
        status: str,
        summary: str,
        findings: tuple[str, ...] = (),
        owner_actions: tuple[str, ...] = (),
    ) -> None:
        self.status = status
        self.summary = summary
        self.findings = findings
        self.owner_actions = owner_actions

    @property
    def exit_code(self) -> int:
        if self.status == STATUS_READY:
            return EXIT_READY
        if self.status == STATUS_BLOCKED:
            return EXIT_BLOCKED
        return EXIT_FAILED


class _DownloadAnchorParser(HTMLParser):
    def __init__(self, href_is_download: Callable[[str], bool]) -> None:
        super().__init__(convert_charrefs=True)
        self._href_is_download = href_is_download
        self.hrefs: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.lower() != "a":
            return
        mapping = {key.lower(): (value or "") for key, value in attrs}
        href = mapping.get("href", "").strip()
        if "download" in mapping or self._href_is_download(href):
            self.hrefs.append(href or "(missing href)")


def _load_sibling(module_name: str) -> Any:
    path = TOOLS / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(
        f"winsvpn_public_download_{module_name}", path
    )
    if spec is None or spec.loader is None:
        raise PublicDownloadGateError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
        raise
    return module


def read_source(root: Path, relative: Path) -> str:
    path = root / relative
    try:
        info = path.lstat()
    except OSError as exc:
        raise PublicDownloadGateError(f"{relative} is missing or unreadable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PublicDownloadGateError(
            f"{relative} must be one regular, non-hardlinked file"
        )
    if info.st_size < 1 or info.st_size > MAX_SOURCE_BYTES:
        raise PublicDownloadGateError(f"{relative} has an invalid source size")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PublicDownloadGateError(f"{relative} cannot be read: {exc}") from exc
    after = path.stat()
    if (
        after.st_dev != info.st_dev
        or after.st_ino != info.st_ino
        or after.st_size != info.st_size
        or after.st_mtime_ns != info.st_mtime_ns
    ):
        raise PublicDownloadGateError(f"{relative} changed while it was read")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicDownloadGateError(f"{relative} is not UTF-8") from exc


def load_manifest(root: Path) -> dict[str, Any]:
    raw = read_source(root, MANIFEST_RELATIVE)

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PublicDownloadGateError(
                    f"{MANIFEST_RELATIVE} contains duplicate JSON key {key}"
                )
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise PublicDownloadGateError(
            f"{MANIFEST_RELATIVE} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise PublicDownloadGateError(f"{MANIFEST_RELATIVE} root must be an object")
    return payload


def _public_text_paths(root: Path) -> tuple[Path, ...]:
    candidates: list[Path] = []
    for relative_root in (WEB_RELATIVE, NETLIFY_FUNCTIONS_RELATIVE):
        absolute = root / relative_root
        if not absolute.is_dir():
            raise PublicDownloadGateError(f"{relative_root} directory is missing")
        for path in absolute.rglob("*"):
            if path.is_symlink():
                raise PublicDownloadGateError(
                    f"{path.relative_to(root)} must not be a symlink"
                )
            if not path.is_file():
                continue
            if path.suffix.lower() in PUBLIC_SOURCE_SUFFIXES or path.name in {
                "_redirects",
                "_headers",
                ".assetsignore",
            }:
                relative = path.relative_to(root)
                if relative in {
                    WEB_RELATIVE / "releases" / "download-custody.json",
                }:
                    continue
                candidates.append(relative)
    return tuple(sorted(set(candidates)))


def _entry_platform(entry_id: str) -> str:
    """windows-x64 -> windows; android/macos/ios are already platform ids."""
    return entry_id.split("-", 1)[0]


def _available_urls(payload: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return available URLs and the platforms with no available entry.

    A platform counts as pending for public-claim checks only while none of its
    per-architecture entries is available (owner ruling 2026-10-25 allows a
    per-platform launch, so other platforms may remain pending).
    """
    available: set[str] = set()
    pending_platforms: set[str] = set()
    available_platforms: set[str] = set()
    entries = payload.get("artifacts")
    if not isinstance(entries, list):
        return available, pending_platforms
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            continue
        platform_id = _entry_platform(entry["id"])
        if entry.get("status") in {PENDING_STATUS, STORE_PENDING_STATUS}:
            pending_platforms.add(platform_id)
        elif entry.get("status") == AVAILABLE_STATUS:
            available_platforms.add(platform_id)
            delivery = entry.get("delivery")
            if isinstance(delivery, dict) and isinstance(delivery.get("url"), str):
                available.add(delivery["url"])
    return available, pending_platforms - available_platforms


def _availability_claim_errors(
    relative: Path, text: str, pending_platforms: set[str]
) -> list[str]:
    errors: list[str] = []
    lowered = re.sub(r"\s+", " ", text.lower())
    all_aliases = sorted(
        {alias for aliases in PLATFORM_ALIASES.values() for alias in aliases},
        key=len,
        reverse=True,
    )
    alias_pattern = "(?:" + "|".join(re.escape(item) for item in all_aliases) + ")"
    subject_pattern = rf"{alias_pattern}(?:\s*(?:,|and|&)\s*{alias_pattern})*"
    claim_patterns = (
        rf"\b(?P<subject>{subject_pattern})\s+downloads?\s+(?:are|is)\s+(?:now\s+)?available\b",
        rf"\bdownloads?\s+for\s+(?P<subject>{subject_pattern})\s+(?:are|is)\s+(?:now\s+)?available\b",
        rf"\b(?P<subject>{subject_pattern})\s+(?:app|installer)\s+(?:are|is)\s+(?:now\s+)?available\b",
        rf"\b(?P<subject>{subject_pattern})\s+(?:are|is)\s+(?:now\s+)?available\s+(?:at|from|on|in)\s+(?:https?://|winsvpn\.org|(?:the\s+)?(?:app|play|microsoft)\s+store|flathub)\b",
    )
    claimed: set[str] = set()
    for pattern in claim_patterns:
        for match in re.finditer(pattern, lowered, flags=re.IGNORECASE):
            subject = match.group("subject")
            for platform_id, aliases in PLATFORM_ALIASES.items():
                if any(re.search(rf"\b{re.escape(alias)}\b", subject) for alias in aliases):
                    claimed.add(platform_id)
    for platform_id in sorted(claimed & pending_platforms):
        errors.append(
            f"{relative} hard-codes {platform_id} download availability while the manifest is pending"
        )
    return errors


def public_source_errors(
    root: Path, payload: dict[str, Any], audit: Any, live_gate: Any
) -> list[str]:
    errors = [
        f"manifest: {message}" for message in audit.download_manifest_errors(payload)
    ]
    errors.extend(
        f"web/{message}" for message in audit.public_download_marker_errors(root / WEB_RELATIVE)
    )

    available_urls, pending_platforms = _available_urls(payload)
    for relative in _public_text_paths(root):
        text = read_source(root, relative)
        if relative.is_relative_to(NETLIFY_FUNCTIONS_RELATIVE):
            lowered = audit.without_pinned_github_release(text).lower()
            for marker, description in audit.STALE_PUBLIC_DOWNLOAD_MARKERS.items():
                if marker.lower() in lowered:
                    errors.append(f"{relative} contains {description}")
        errors.extend(_availability_claim_errors(relative, text, pending_platforms))
        if relative.suffix.lower() == ".html":
            parser = _DownloadAnchorParser(live_gate.is_active_download_href)
            try:
                parser.feed(text)
                parser.close()
            except Exception as exc:
                errors.append(
                    f"{relative} could not be parsed fail-closed: {type(exc).__name__}"
                )
                continue
            for href in parser.hrefs:
                if href not in available_urls:
                    errors.append(
                        f"{relative} exposes a download/store anchor not exactly bound by the manifest: {href}"
                    )

    index = read_source(root, WEB_RELATIVE / "index.html")
    errors.extend(
        f"web/index.html: {message}"
        for message in audit.browser_download_contract_errors(index)
    )
    for relative in REQUIRED_SUPPORT_SOURCES:
        source = read_source(root, relative)
        if RELEASE_AUTHORITY_MARKER not in source or PENDING_MARKER not in source.lower():
            errors.append(
                f"{relative} does not bind support answers to the manifest release authority"
            )
    errors.extend(download_directory_errors(root, payload))
    errors.extend(publication_route_errors(root, bool(available_urls), audit))
    return errors


def download_directory_errors(root: Path, payload: dict[str, Any]) -> list[str]:
    downloads = root / DOWNLOADS_RELATIVE
    if not downloads.exists():
        return []
    if downloads.is_symlink() or not downloads.is_dir():
        return [f"{DOWNLOADS_RELATIVE} must be a real directory"]

    bound_names: set[str] = set()
    entries = payload.get("artifacts")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("status") != AVAILABLE_STATUS:
                continue
            delivery = entry.get("delivery")
            artifact = entry.get("artifact")
            if (
                not isinstance(delivery, dict)
                or delivery.get("kind") not in {"direct", "github_release"}
                or not isinstance(artifact, dict)
            ):
                continue
            filename = artifact.get("filename")
            if not isinstance(filename, str) or not filename:
                continue
            bound_names.update({filename, f"{filename}.sha256"})
            if str(entry.get("id")).startswith("linux"):
                bound_names.add(f"{filename}.sigstore.json")
            for field in (
                "privacy",
                "release_receipt",
                "publication_receipt",
                "winn_provenance",
                "windows_verification",
            ):
                binding = artifact.get(field)
                if isinstance(binding, dict) and isinstance(
                    binding.get("receipt_filename"), str
                ):
                    bound_names.add(binding["receipt_filename"])

    present: set[str] = set()
    errors: list[str] = []
    for path in downloads.iterdir():
        relative = path.relative_to(root)
        try:
            info = path.lstat()
        except OSError as exc:
            errors.append(f"{relative} cannot be inspected: {exc}")
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            errors.append(f"{relative} is not one regular, non-hardlinked file")
            continue
        present.add(path.name)
    unbound = sorted(present - bound_names)
    if unbound:
        errors.append(
            f"{DOWNLOADS_RELATIVE} contains manifest-unbound publication files: "
            + ", ".join(unbound[:8])
        )
    return errors


def publication_route_errors(
    root: Path, has_available: bool, audit: Any | None = None
) -> list[str]:
    errors: list[str] = []
    redirects = read_source(root, REDIRECTS_RELATIVE)
    worker = read_source(root, WORKER_RELATIVE)
    assetsignore = read_source(root, ASSETSIGNORE_RELATIVE)

    redirect_lines = [
        line.strip()
        for line in redirects.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "/downloads" in line
    ]
    if redirect_lines:
        errors.append(
            f"{REDIRECTS_RELATIVE} publishes a download redirect: {'; '.join(redirect_lines)}"
        )
    if "const downloadRedirects = new Map();" not in worker:
        errors.append(f"{WORKER_RELATIVE} download redirect map is not exactly empty")
    # The Worker may name the one pinned GitHub release prefix (it authorizes
    # that entry's Pages-hosted receipts); any other GitHub release URL is a
    # placeholder and stays refused.
    scrubbed = audit.without_pinned_github_release(worker) if audit is not None else worker
    if "winsvpn-downloads/releases/download/" in scrubbed:
        errors.append(f"{WORKER_RELATIVE} contains a GitHub publication placeholder")

    ignores_downloads = any(
        line.strip() == "downloads/"
        for line in assetsignore.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    routes_download_assets = (
        'if (canonical === "/downloads" || canonical.startsWith("/downloads/")) {'
        in worker
        and 'return { action: "asset" };' in worker
        and 'return { action: "not_found" };' in worker
        and "downloadManifestBoundPaths" in worker
        and 'deliveryUrl.origin !== "https://winsvpn.org"' in worker
        and 'downloadDecision.action === "asset"' in worker
        and 'contentType.toLowerCase().includes("text/html")' in worker
        and '"x-wins-download-route": "static-asset"' in worker
        and 'return { action: "redirect"' not in worker
        and "env.DOWNLOADS_BUCKET" in worker
        and "downloadR2ObjectKey" in worker
        and "verifiedDownloadStream" in worker
        and '"x-wins-download-route": "r2-verified"' in worker
    )
    if has_available:
        if ignores_downloads:
            errors.append(
                f"{ASSETSIGNORE_RELATIVE} still excludes manifest-available direct artifacts"
            )
        if not routes_download_assets:
            errors.append(
                f"{WORKER_RELATIVE} does not route manifest-available direct artifacts through static assets"
            )
    else:
        if not ignores_downloads:
            errors.append(
                f"{ASSETSIGNORE_RELATIVE} must exclude downloads while every platform is pending"
            )
        if not routes_download_assets:
            errors.append(
                f"{WORKER_RELATIVE} must keep pending paths blocked and prepare manifest-bound static assets"
            )
    return errors


def evaluate_tree(
    root: Path,
    *,
    custody_evaluator: Callable[[Path], Any] | None = None,
) -> GateReport:
    try:
        audit = _load_sibling("website_security_audit")
        live_gate = _load_sibling("public_website_download_live_gate")
        custody = _load_sibling("website_download_custody")
        payload = load_manifest(root)
        source_errors = public_source_errors(root, payload, audit, live_gate)
    except Exception as exc:
        message = f"FAIL website public download gate could not evaluate safely: {exc}"
        return GateReport(STATUS_FAILED, message, (str(exc),))

    if source_errors:
        summary = "FAIL website public download gate: " + "; ".join(source_errors)
        return GateReport(STATUS_FAILED, summary, tuple(source_errors))

    try:
        evaluator = custody_evaluator or custody.evaluate_tree
        custody_report = evaluator(root)
    except Exception as exc:
        message = f"FAIL website public download custody could not evaluate safely: {exc}"
        return GateReport(STATUS_FAILED, message, (str(exc),))

    if custody_report.ok and custody_report.status == custody.AVAILABLE_STATUS:
        entries = payload.get("artifacts")
        available_ids = [
            entry.get("id")
            for entry in entries
            if isinstance(entry, dict) and entry.get("status") == AVAILABLE_STATUS
        ] if isinstance(entries, list) else []
        if not available_ids:
            message = (
                "trusted custody reported available, but the public manifest makes "
                "no entry available"
            )
            return GateReport(STATUS_FAILED, f"FAIL {message}", (message,))
        unavailable = [
            f"{entry.get('id')}={entry.get('status')}"
            for entry in entries
            if isinstance(entry, dict) and entry.get("status") != AVAILABLE_STATUS
        ]
        summary = (
            "PASS website public downloads are bound to exact current "
            f"{custody.CANONICAL_RELEASE} artifacts and manifest-authorized links: "
            f"available {', '.join(str(item) for item in available_ids)}; "
            f"not published {', '.join(unavailable) or 'none'}"
        )
        return GateReport(STATUS_READY, summary)

    if (
        not custody_report.ok
        and custody_report.status == custody.PENDING_STATUS
        and str(custody_report.summary).startswith("PENDING ")
    ):
        owner_actions = tuple(str(item) for item in custody_report.findings)
        summary = (
            "BLOCKED website source is fail-closed, but owner-signed artifacts, "
            "store URLs, and publication evidence are not complete"
        )
        return GateReport(STATUS_BLOCKED, summary, (), owner_actions)

    detail = str(custody_report.summary)
    summary = f"FAIL website public download custody did not pass: {detail}"
    findings = tuple(str(item) for item in custody_report.findings) or (detail,)
    return GateReport(STATUS_FAILED, summary, findings)


def evaluate_repository() -> GateReport:
    return evaluate_tree(ROOT)


def render_report(report: GateReport) -> str:
    lines = [report.status.upper(), report.summary]
    if report.findings:
        lines.append("findings:")
        lines.extend(f"- {item}" for item in report.findings)
    if report.owner_actions:
        lines.append("owner actions:")
        lines.extend(f"- {item}" for item in report.owner_actions)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        print(f"usage: {Path(sys.argv[0]).name}", file=sys.stderr)
        return EXIT_USAGE
    report = evaluate_repository()
    sys.stdout.write(render_report(report))
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
