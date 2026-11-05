#!/usr/bin/env python3
"""Load a local exact known-server-secret inventory without disclosing values.

The inventory is accepted only from an explicit absolute path outside the
repository. Values stay in process memory and are streamed to scanner APIs.
Public output is limited to revision, sorted labels, counts, and identity
metadata. Values and value-derived hashes are never printed or returned by
summary APIs.

Release coverage comes only from ``load_authenticated_secret_inventory``,
which reads the inventory named by the ``WINS_RELEASE_SECRET_INVENTORY``
environment variable. That value must be an exact absolute path outside the
repository, naming a regular, non-symlink, single-link file owned by the
current user with mode 0600 or stricter. A missing or invalid inventory
refuses, so the exact secret scan cannot be skipped. Candidate-supplied
contracts and constructor booleans cannot mark an inventory as release
coverage.

Durable secrets remain server-side. An unauthenticated inventory is not
release coverage and cannot authorize embedding secrets in a client.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Callable, Final


SCHEMA_VERSION: Final[int] = 1
CONTRACT_SCHEMA_VERSION: Final[int] = 1
CONTRACT_NAME: Final[str] = "winsvpn-secret-inventory-v1"
INVENTORY_ENV: Final[str] = "WINS_RELEASE_SECRET_INVENTORY"
TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {"schema_version", "revision", "secrets"}
)
CONTRACT_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {"schema_version", "contract", "revision", "labels", "inventory_digest", "identity"}
)
TRANSCRIPT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "chat",
        "choices",
        "completion",
        "completions",
        "content",
        "conversation",
        "conversations",
        "delta",
        "export",
        "exports",
        "message",
        "messages",
        "role",
        "tool_calls",
        "transcript",
    }
)
LABEL_RE: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9_]{2,80}")
DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
MAX_INVENTORY_BYTES: Final[int] = 64 * 1024
MAX_CONTRACT_BYTES: Final[int] = 16 * 1024
# Per-field maxima and these aggregate document caps are independent defenses;
# callers may not combine every field maximum in one accepted document.
MAX_SECRET_COUNT: Final[int] = 256
MIN_VALUE_CHARS: Final[int] = 12
MAX_VALUE_CHARS: Final[int] = 8192
MAX_REVISION_CHARS: Final[int] = 128
ALLOWED_VALUE_CONTROLS: Final[frozenset[str]] = frozenset({"\t", "\n", "\r"})
IDENTITY_FIELD_COUNT: Final[int] = 9
DURABLE_SECRET_CUSTODY: Final[str] = "server-side"
_DESCRIPTOR_RELATIVE_OPEN_SUPPORTED: Final[bool] = os.open in os.supports_dir_fd
_DESCRIPTOR_RELATIVE_STAT_SUPPORTED: Final[bool] = os.stat in os.supports_dir_fd

# Tests may assign a callable after each parent directory is bound through
# openat and before child lookup continues. Production loading leaves this unset.
_POST_PARENT_BIND_HOOK: Callable[[pathlib.Path, int], None] | None = None


class InventoryError(RuntimeError):
    """Fail-closed inventory refusal. Messages must never contain secret values."""


class InventoryContract:
    """Legacy public identity object. It is never an authentication authority."""

    __slots__ = ("revision", "labels", "digest", "identity")

    def __init__(
        self,
        revision: str,
        labels: tuple[str, ...],
        digest: str,
        identity: tuple[int, ...],
    ) -> None:
        self.revision = revision
        self.labels = tuple(labels)
        self.digest = digest
        self.identity = tuple(identity)

    def public_summary(self) -> dict[str, object]:
        return {
            "revision": self.revision,
            "labels": list(self.labels),
            "label_count": len(self.labels),
            "inventory_digest": self.digest,
        }

    def __repr__(self) -> str:
        return (
            "InventoryContract("
            f"revision={self.revision!r}, "
            f"labels={list(self.labels)!r}, "
            f"label_count={len(self.labels)})"
        )


@dataclass(frozen=True)
class _InventoryAuthorization:
    """Release-loader bindings for one inventory read. Never contains secret values."""

    revision: str
    labels: tuple[str, ...]
    inventory_digest: str
    inventory_identity: tuple[int, ...]
    inventory_path: pathlib.Path
    repository_root: pathlib.Path


class SecretInventory:
    """In-memory inventory. ``repr`` and public summaries omit secret values."""

    __slots__ = (
        "revision",
        "_secrets",
        "digest",
        "identity",
        "_authorization",
    )

    def __init__(
        self,
        revision: str,
        secrets: Mapping[str, str],
        *,
        digest: str = "",
        identity: tuple[int, ...] = (),
    ) -> None:
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "_secrets", tuple(sorted(secrets.items())))
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "identity", tuple(identity))
        object.__setattr__(self, "_authorization", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("SecretInventory is immutable")

    @property
    def authenticated(self) -> bool:
        authorization = self._authorization
        return bool(
            type(authorization) is _InventoryAuthorization
            and authorization.revision == self.revision
            and authorization.labels == self.labels
            and authorization.inventory_digest == self.digest
            and authorization.inventory_identity == self.identity
        )

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(label for label, _value in self._secrets)

    @property
    def label_count(self) -> int:
        return len(self._secrets)

    @property
    def unique_value_count(self) -> int:
        return len({value for _label, value in self._secrets})

    def _stream_secret_values(self) -> Iterator[tuple[str, str]]:
        """Private parser/test stream. Release callers must rebind fixed custody."""
        yield from self._secrets

    def stream_secret_values(self) -> Iterator[tuple[str, str]]:
        """Fail-closed compatibility stub for the former unauthenticated API."""
        raise InventoryError(
            "direct secret streaming is not release coverage; "
            "use release_secret_values on load_authenticated_secret_inventory"
        )

    def public_summary(self) -> dict[str, object]:
        summary: dict[str, object] = {
            "revision": self.revision,
            "labels": list(self.labels),
            "label_count": self.label_count,
            "unique_value_count": self.unique_value_count,
            "authenticated": self.authenticated,
            "durable_secret_custody": DURABLE_SECRET_CUSTODY,
        }
        authorization = self._authorization
        if self.authenticated and type(authorization) is _InventoryAuthorization:
            summary.update(
                {
                    "inventory_source": INVENTORY_ENV,
                    "inventory_sha256": authorization.inventory_digest,
                }
            )
        return summary

    def __repr__(self) -> str:
        return (
            "SecretInventory("
            f"revision={self.revision!r}, "
            f"labels={list(self.labels)!r}, "
            f"label_count={self.label_count}, "
            f"unique_value_count={self.unique_value_count}, "
            f"authenticated={self.authenticated})"
        )


def _make_authenticated_inventory(
    loaded: SecretInventory, authorization: _InventoryAuthorization
) -> SecretInventory:
    """Construct the only authenticated inventory representation."""
    result = SecretInventory(
        loaded.revision,
        dict(loaded._stream_secret_values()),
        digest=loaded.digest,
        identity=loaded.identity,
    )
    object.__setattr__(result, "_authorization", authorization)
    return result


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """Exact file identity, including size and timestamps."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _pathname_identity(info: os.stat_result) -> tuple[int, ...]:
    """Stable path identity. Directory ctime/mtime/nlink/size churn is not substitution."""
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
    )


class _BoundParent:
    """One descriptor-bound path component plus the child opened from it."""

    __slots__ = ("fd", "path", "lexical", "symlink", "child_name", "child")

    def __init__(
        self,
        fd: int,
        path: pathlib.Path,
        lexical: tuple[int, ...],
        *,
        symlink: bool,
    ) -> None:
        self.fd = fd
        self.path = path
        self.lexical = lexical
        self.symlink = symlink
        self.child_name: str | None = None
        self.child: tuple[int, ...] | None = None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate JSON key")
        result[key] = value
    return result


def _is_inside_repository(path: pathlib.Path, repository_root: pathlib.Path) -> bool:
    try:
        path.resolve().relative_to(repository_root.resolve())
    except ValueError:
        return False
    return True


def _walk_forbidden_shapes(value: object) -> None:
    if type(value) is dict:
        if set(value) & TRANSCRIPT_KEYS:
            raise InventoryError("transcript/message schema is not a secret inventory")
        for nested in value.values():
            _walk_forbidden_shapes(nested)
        return
    if type(value) is list:
        for nested in value:
            _walk_forbidden_shapes(nested)


def _validate_revision(value: object) -> str:
    if type(value) is not str or not value or not value.isascii():
        raise InventoryError("secret inventory revision must be nonempty ASCII")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InventoryError("secret inventory revision contains a control character")
    if value.strip() != value or len(value) > MAX_REVISION_CHARS:
        raise InventoryError("secret inventory revision is padded or exceeds the bound")
    return value


def _validate_label(label: object) -> str:
    if type(label) is not str or not label.isascii() or LABEL_RE.fullmatch(label) is None:
        raise InventoryError("secret inventory contains an invalid ASCII label")
    return label


def _validate_secret_value(value: object) -> str:
    if type(value) is not str or not value:
        raise InventoryError("secret inventory values must be nonempty strings")
    if len(value) < MIN_VALUE_CHARS or len(value) > MAX_VALUE_CHARS:
        raise InventoryError("secret inventory value length is outside the accepted bound")
    if "\x00" in value:
        raise InventoryError("secret inventory values must not contain NUL")
    if any(
        ord(character) < 32 and character not in ALLOWED_VALUE_CONTROLS
        for character in value
    ):
        raise InventoryError("secret inventory value contains a disallowed control character")
    return value


def _value_derived_hashes(value: str) -> tuple[str, ...]:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return (digest, digest.upper())


def _field_contains_secret_material(field: str, secrets: Mapping[str, str]) -> bool:
    for value in secrets.values():
        if field == value or value in field:
            return True
        for digest in _value_derived_hashes(value):
            if field == digest or digest in field:
                return True
    return False


def _reject_secret_bearing_public_fields(
    revision: str, secrets: Mapping[str, str], extra_fields: tuple[str, ...] = ()
) -> None:
    fields = (revision, *secrets, *extra_fields)
    for field in fields:
        if _field_contains_secret_material(field, secrets):
            raise InventoryError("secret inventory public fields must not carry secret material")


def _parse_json_object(payload: bytes, *, kind: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InventoryError(f"{kind} is not UTF-8") from None
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except InventoryError:
        raise
    except json.JSONDecodeError:
        raise InventoryError(f"{kind} is not valid JSON") from None
    if type(document) is not dict:
        raise InventoryError(f"{kind} must be one JSON object")
    _walk_forbidden_shapes(document)
    return document


def _parse_document(
    payload: bytes, *, digest: str, identity: tuple[int, ...]
) -> SecretInventory:
    document = _parse_json_object(payload, kind="secret inventory")
    keys = set(document)
    if keys != TOP_LEVEL_KEYS:
        raise InventoryError("secret inventory top-level schema is not exact")
    schema_version = document.get("schema_version")
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise InventoryError("secret inventory schema_version is not the accepted version")
    revision = _validate_revision(document.get("revision"))
    raw_secrets = document.get("secrets")
    if type(raw_secrets) is not dict:
        raise InventoryError("secret inventory secrets must be one JSON object")
    if not raw_secrets:
        raise InventoryError("secret inventory secrets must contain at least one label")
    if len(raw_secrets) > MAX_SECRET_COUNT:
        raise InventoryError("secret inventory exceeds the accepted label count")
    secrets: dict[str, str] = {}
    for raw_label, raw_value in raw_secrets.items():
        label = _validate_label(raw_label)
        if label in secrets:
            raise InventoryError("duplicate JSON key")
        secrets[label] = _validate_secret_value(raw_value)
    _reject_secret_bearing_public_fields(revision, secrets, extra_fields=(digest,))
    return SecretInventory(
        revision,
        secrets,
        digest=digest,
        identity=identity,
    )


def _openat_available() -> bool:
    return (
        _DESCRIPTOR_RELATIVE_OPEN_SUPPORTED
        and _DESCRIPTOR_RELATIVE_STAT_SUPPORTED
    )


def _open_nofollow_flags(*, directory: bool = False, follow_root: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not follow_root:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow == 0:
            raise InventoryError("secret inventory loading requires O_NOFOLLOW")
        flags |= nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if directory_flag == 0:
            raise InventoryError("secret inventory loading requires O_DIRECTORY")
        flags |= directory_flag
    return flags


def _close_fds(fds: list[int]) -> None:
    for descriptor in fds:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _lstat_path(path: pathlib.Path, *, missing: str) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError:
        raise InventoryError(missing) from None


def _peek_component(
    current_fd: int, current_path: pathlib.Path, part: str, *, missing: str
) -> os.stat_result:
    try:
        return os.stat(part, dir_fd=current_fd, follow_symlinks=False)
    except OSError:
        raise InventoryError(missing) from None


def _open_component(
    current_fd: int, current_path: pathlib.Path, part: str, flags: int, *, regular: str
) -> int:
    try:
        return os.open(part, flags, dir_fd=current_fd)
    except OSError:
        raise InventoryError(regular) from None


def _is_special_file(mode: int) -> bool:
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def _descriptor_child_stat(
    parent: _BoundParent, *, missing: str
) -> os.stat_result:
    if parent.child_name is None:
        raise InventoryError(missing)
    try:
        return os.stat(
            parent.child_name,
            dir_fd=parent.fd,
            follow_symlinks=False,
        )
    except OSError:
        raise InventoryError(missing) from None


def _confirm_bound_parents(
    parents: list[_BoundParent],
    path: pathlib.Path,
    *,
    missing: str,
    replaced: str,
    parent_replaced: str,
) -> None:
    for parent in parents:
        parent_after = _lstat_path(parent.path, missing=missing)
        if _pathname_identity(parent_after) != parent.lexical:
            raise InventoryError(parent_replaced)
        if parent.symlink:
            if not stat.S_ISLNK(parent_after.st_mode):
                raise InventoryError(parent_replaced)
        elif not stat.S_ISDIR(parent_after.st_mode):
            raise InventoryError(parent_replaced)
        if parent.child_name is None or parent.child is None:
            continue
        child_path = parent.path / parent.child_name
        child_message = replaced if child_path == path else parent_replaced
        child_after = _descriptor_child_stat(parent, missing=child_message)
        if _pathname_identity(child_after) != parent.child:
            raise InventoryError(child_message)


def _descriptor_walk_regular_file(
    path: pathlib.Path,
    *,
    maximum: int,
    missing: str,
    replaced: str,
    regular: str,
    owner_only: bool,
    allowed_uids: frozenset[int] | None = None,
) -> tuple[bytes, tuple[int, ...], tuple[tuple[int, ...], ...]]:
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise InventoryError("secret inventory path must be an explicit absolute path")
    if not _openat_available():
        raise InventoryError(
            "secret inventory loading requires descriptor-relative open and stat"
        )
    file_flags = _open_nofollow_flags()
    dir_nofollow_flags = _open_nofollow_flags(directory=True)
    dir_follow_flags = _open_nofollow_flags(directory=True, follow_root=True)
    parent_fds: list[int] = []
    parents: list[_BoundParent] = []
    fd = -1
    before: os.stat_result | None = None
    chunks: list[bytes] = []
    try:
        initial = _lstat_path(path, missing=missing)
        if (
            stat.S_ISLNK(initial.st_mode)
            or not stat.S_ISREG(initial.st_mode)
            or _is_special_file(initial.st_mode)
        ):
            raise InventoryError(regular)
        try:
            current_fd = os.open(path.anchor, dir_follow_flags)
        except OSError:
            raise InventoryError(missing) from None
        parent_fds.append(current_fd)
        anchor_path = pathlib.Path(path.anchor)
        anchor_info = _lstat_path(anchor_path, missing=missing)
        parents.append(
            _BoundParent(
                current_fd,
                anchor_path,
                _pathname_identity(anchor_info),
                symlink=stat.S_ISLNK(anchor_info.st_mode),
            )
        )
        current_path = anchor_path
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            hook = _POST_PARENT_BIND_HOOK
            if hook is not None:
                hook(path, index)
            current_path = current_path / part
            peeked = _peek_component(current_fd, current_path, part, missing=missing)
            last = index == len(parts) - 1
            parents[-1].child_name = part
            parents[-1].child = _pathname_identity(peeked)
            if last:
                if (
                    stat.S_ISLNK(peeked.st_mode)
                    or not stat.S_ISREG(peeked.st_mode)
                    or _is_special_file(peeked.st_mode)
                ):
                    raise InventoryError(regular)
                component_flags = file_flags
            elif stat.S_ISLNK(peeked.st_mode):
                # Directory symlinks such as Darwin `/var` are followed after
                # binding the lexical link identity for swap/restore checks.
                component_flags = dir_follow_flags
            elif stat.S_ISDIR(peeked.st_mode):
                if _is_special_file(peeked.st_mode):
                    raise InventoryError(regular)
                component_flags = dir_nofollow_flags
            else:
                raise InventoryError(regular)
            next_fd = _open_component(
                current_fd, current_path, part, component_flags, regular=regular
            )
            opened = os.fstat(next_fd)
            if last:
                if _identity(peeked) != _identity(opened):
                    os.close(next_fd)
                    raise InventoryError(replaced)
            elif not stat.S_ISLNK(peeked.st_mode):
                if _pathname_identity(peeked) != _pathname_identity(opened):
                    os.close(next_fd)
                    raise InventoryError(replaced)
            if last:
                fd = next_fd
            else:
                parent_fds.append(next_fd)
                parents.append(
                    _BoundParent(
                        next_fd,
                        current_path,
                        _pathname_identity(peeked),
                        symlink=stat.S_ISLNK(peeked.st_mode),
                    )
                )
                current_fd = next_fd
        before = os.fstat(fd)
        path_before = _lstat_path(path, missing=missing)
        if _identity(initial) != _identity(before) or _identity(before) != _identity(path_before):
            raise InventoryError(replaced)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise InventoryError(regular)
        if before.st_nlink != 1:
            raise InventoryError("secret inventory must have link count 1")
        accepted_uids = (
            frozenset({os.getuid()}) if allowed_uids is None else allowed_uids
        )
        if before.st_uid not in accepted_uids:
            if allowed_uids is None:
                raise InventoryError("secret inventory must be owned by the current user")
            raise InventoryError("secret inventory source has an untrusted owner")
        mode = stat.S_IMODE(before.st_mode)
        if owner_only:
            if mode & 0o177:
                raise InventoryError(
                    "secret inventory must use mode 0600 or stricter without execute bits"
                )
        elif mode & 0o022:
            raise InventoryError("secret inventory contract must not be group or world writable")
        if before.st_size <= 0 or before.st_size > maximum:
            raise InventoryError("secret inventory size is outside the accepted bound")
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                raise InventoryError("secret inventory ended before its declared size")
            remaining -= len(block)
            chunks.append(block)
        extra_byte = os.read(fd, 1)
        if extra_byte:
            raise InventoryError("secret inventory size changed while it was read")
        after = os.fstat(fd)
        path_after = _lstat_path(path, missing=missing)
        if _identity(before) != _identity(after) or _identity(after) != _identity(path_after):
            raise InventoryError("secret inventory changed while it was read")
        _confirm_bound_parents(
            parents,
            path,
            missing=missing,
            replaced=replaced,
            parent_replaced="secret inventory parent path was replaced",
        )
    finally:
        if fd >= 0:
            parent_fds.append(fd)
        _close_fds(parent_fds)
    if before is None:
        raise InventoryError(missing)
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        raise InventoryError("secret inventory size is outside the accepted bound")
    return payload, _identity(before), tuple(parent.lexical for parent in parents)


def _read_inventory_bytes(path: pathlib.Path) -> tuple[bytes, tuple[int, ...]]:
    payload, identity, _parents = _descriptor_walk_regular_file(
        path,
        maximum=MAX_INVENTORY_BYTES,
        missing="secret inventory is missing or unreadable",
        replaced="secret inventory was replaced",
        regular="secret inventory must be a regular non-symlink file",
        owner_only=True,
    )
    return payload, identity


def _parse_identity(value: object) -> tuple[int, ...]:
    if type(value) is not list or len(value) != IDENTITY_FIELD_COUNT:
        raise InventoryError("secret inventory contract identity is not exact")
    identity: list[int] = []
    for item in value:
        if type(item) is not int:
            raise InventoryError("secret inventory contract identity is not exact")
        if item < 0:
            raise InventoryError("secret inventory contract identity is not exact")
        identity.append(item)
    return tuple(identity)


def _parse_contract_document(payload: bytes) -> tuple[str, tuple[str, ...], str, tuple[int, ...]]:
    document = _parse_json_object(payload, kind="secret inventory contract")
    if set(document) != CONTRACT_TOP_LEVEL_KEYS:
        raise InventoryError("secret inventory contract top-level schema is not exact")
    schema_version = document.get("schema_version")
    if type(schema_version) is not int or schema_version != CONTRACT_SCHEMA_VERSION:
        raise InventoryError("secret inventory contract schema_version is not the accepted version")
    contract_name = document.get("contract")
    if type(contract_name) is not str or contract_name != CONTRACT_NAME:
        raise InventoryError("secret inventory contract name is not the accepted contract")
    revision = _validate_revision(document.get("revision"))
    raw_labels = document.get("labels")
    if type(raw_labels) is not list or not raw_labels:
        raise InventoryError("secret inventory contract labels must be a nonempty array")
    if len(raw_labels) > MAX_SECRET_COUNT:
        raise InventoryError("secret inventory exceeds the accepted label count")
    labels: list[str] = []
    seen: set[str] = set()
    for raw_label in raw_labels:
        label = _validate_label(raw_label)
        if label in seen:
            raise InventoryError("duplicate JSON key")
        seen.add(label)
        labels.append(label)
    ordered = tuple(sorted(labels))
    digest = document.get("inventory_digest")
    if type(digest) is not str or DIGEST_RE.fullmatch(digest) is None:
        raise InventoryError("secret inventory contract digest is not an exact SHA-256")
    identity = _parse_identity(document.get("identity"))
    if _field_contains_secret_material(revision, {}) or any(
        _field_contains_secret_material(label, {}) for label in ordered
    ):
        raise InventoryError("secret inventory public fields must not carry secret material")
    return revision, ordered, digest, identity


def authenticate_inventory_contract(
    *,
    revision: str,
    labels: tuple[str, ...] | list[str],
    digest: str,
    identity: tuple[int, ...],
) -> InventoryContract:
    """Legacy compatibility stub. Public values cannot authenticate release coverage."""
    del revision, labels, digest, identity
    raise InventoryError(
        "candidate-controlled authorization cannot self-authorize; "
        f"use load_authenticated_secret_inventory with {INVENTORY_ENV}"
    )


def load_inventory_contract(
    path: pathlib.Path,
    *,
    repository_root: pathlib.Path,
) -> InventoryContract:
    """Legacy compatibility stub. Caller-selected contracts are never trusted."""
    del path, repository_root
    raise InventoryError(
        "candidate-controlled authorization cannot self-authorize; "
        f"use load_authenticated_secret_inventory with {INVENTORY_ENV}"
    )


def _read_bound_public_file(
    path: pathlib.Path,
    *,
    maximum: int,
    missing: str,
    replaced: str,
    regular: str,
) -> tuple[bytes, tuple[int, ...]]:
    payload, identity, _parents = _descriptor_walk_regular_file(
        path,
        maximum=maximum,
        missing=missing,
        replaced=replaced,
        regular=regular,
        owner_only=False,
    )
    return payload, identity


def _bind_contract(
    loaded: SecretInventory, contract: InventoryContract
) -> SecretInventory:
    del loaded, contract
    raise InventoryError(
        "candidate-controlled authorization cannot self-authorize; "
        f"use load_authenticated_secret_inventory with {INVENTORY_ENV}"
    )


def _configured_inventory_path(repository_root: pathlib.Path) -> pathlib.Path:
    """Return the exact external inventory path named by the release environment."""
    raw = os.environ.get(INVENTORY_ENV)
    if raw is None or raw == "":
        raise InventoryError(
            f"secret inventory is not configured: set {INVENTORY_ENV} to an "
            "absolute path outside the repository"
        )
    if "\x00" in raw or raw != raw.strip():
        raise InventoryError(f"{INVENTORY_ENV} must name an exact absolute path")
    path = pathlib.Path(raw)
    if (
        not path.is_absolute()
        or str(path) != raw
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise InventoryError(f"{INVENTORY_ENV} must name an exact absolute path")
    if _is_inside_repository(path, repository_root):
        raise InventoryError(
            f"{INVENTORY_ENV} must name a path outside the repository"
        )
    return path


def load_authenticated_secret_inventory(
    *, repository_root: pathlib.Path
) -> SecretInventory:
    """Load release coverage from the inventory named by WINS_RELEASE_SECRET_INVENTORY.

    The file must be a regular, non-symlink, single-link file outside the
    repository, owned by the current user with mode 0600 or stricter. Any
    missing or invalid inventory refuses; the exact secret scan is never skipped.
    """
    if not isinstance(repository_root, pathlib.Path):
        repository_root = pathlib.Path(repository_root)
    if not repository_root.is_absolute():
        raise InventoryError("secret inventory repository root must be absolute")
    path = _configured_inventory_path(repository_root)
    payload, identity = _read_inventory_bytes(path)
    digest = hashlib.sha256(payload).hexdigest()
    loaded = _parse_document(payload, digest=digest, identity=identity)
    _reject_secret_bearing_public_fields(
        loaded.revision,
        dict(loaded._stream_secret_values()),
        extra_fields=(digest, str(path), INVENTORY_ENV),
    )
    binding = _InventoryAuthorization(
        revision=loaded.revision,
        labels=loaded.labels,
        inventory_digest=digest,
        inventory_identity=identity,
        inventory_path=path,
        repository_root=repository_root,
    )
    return _make_authenticated_inventory(loaded, binding)


def load_secret_inventory(
    path: pathlib.Path,
    *,
    repository_root: pathlib.Path,
    contract: InventoryContract | None = None,
    require_authenticated: bool = False,
) -> SecretInventory:
    """Load a validated inventory from an explicit absolute external path.

    This is a parser-only, unauthenticated loader retained for tests and generic
    diagnostics. Release coverage must call ``load_authenticated_secret_inventory``.
    Candidate-supplied ``contract`` values always fail closed.
    """
    if not isinstance(path, pathlib.Path):
        path = pathlib.Path(path)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise InventoryError("secret inventory path must be an explicit absolute path")
    if _is_inside_repository(path, repository_root):
        raise InventoryError("secret inventory must be an external path")
    if contract is not None:
        raise InventoryError(
            "candidate-controlled authorization cannot self-authorize; "
            f"use load_authenticated_secret_inventory with {INVENTORY_ENV}"
        )
    if require_authenticated:
        raise InventoryError(
            "release coverage requires load_authenticated_secret_inventory "
            f"with {INVENTORY_ENV}"
        )
    payload, identity = _read_inventory_bytes(path)
    digest = hashlib.sha256(payload).hexdigest()
    return _parse_document(payload, digest=digest, identity=identity)


def release_secret_values(inventory: SecretInventory) -> Iterator[tuple[str, str]]:
    """Stream secrets only from an inventory loaded by the release loader.

    Unauthenticated documents are not release coverage. Durable secrets remain
    server-side; this iterator exists to scan client artifacts for leaks. The
    inventory is read again immediately before use and must be unchanged.
    """
    if not inventory.authenticated:
        raise InventoryError(
            "exact secret scan requires load_authenticated_secret_inventory "
            f"with {INVENTORY_ENV}; unauthenticated inventories are not release "
            "coverage. Durable secrets remain server-side."
        )
    authorization = inventory._authorization
    if type(authorization) is not _InventoryAuthorization:
        raise InventoryError("secret inventory release binding is invalid")
    current = load_authenticated_secret_inventory(
        repository_root=authorization.repository_root
    )
    current_authorization = current._authorization
    if (
        type(current_authorization) is not _InventoryAuthorization
        or current_authorization.inventory_path != authorization.inventory_path
        or current.digest != inventory.digest
        or current.identity != inventory.identity
        or current.labels != inventory.labels
        or current.revision != inventory.revision
    ):
        raise InventoryError("secret inventory changed before release use")
    yield from current._stream_secret_values()
