"""Small fail-closed ASGI security boundary for server-to-server routing."""
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
from collections import defaultdict, deque
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable

from starlette.responses import JSONResponse


PROTECTED_PATHS = {
    "/",
    "/route",
    "/hoppy/escalate",
    "/decisions",
    "/decisions.csv",
    "/stats",
    "/health",
}

# OI-37 (Round 36 treaty): authentication is deny-by-default. Only these paths
# are served without the HMAC admission check (liveness/readiness probes a
# scheduler cannot sign, and the browser favicon); every other http path is
# rejected before a route handler runs, so a newly added endpoint cannot ship
# unauthenticated by accident.
PUBLIC_PATHS = frozenset({"/live", "/ready", "/favicon.ico"})

_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
_REPLAY_SCHEMA_VERSION = 2
_REPLAY_TABLE_SQL = """\
CREATE TABLE replay_nonces (
    nonce_hash BLOB PRIMARY KEY NOT NULL CHECK(length(nonce_hash) = 32),
    accepted_at REAL NOT NULL,
    expires_at REAL NOT NULL CHECK(expires_at >= accepted_at)
) WITHOUT ROWID
"""
_REPLAY_STATE_TABLE_SQL = """\
CREATE TABLE replay_state (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    wall_clock_high_water REAL NOT NULL
) WITHOUT ROWID
"""
_REPLAY_INITIAL_HIGH_WATER = 0.0


class _DeadlineExpired(RuntimeError):
    pass


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as err:
        raise RuntimeError(f"{name} must be an integer") from err
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def max_body_bytes() -> int:
    return _bounded_int("SMART_ROUTER_MAX_BODY_BYTES", 32768, 4096, 262144)


def auth_window_seconds() -> int:
    return _bounded_int("SMART_ROUTER_AUTH_WINDOW_SECONDS", 30, 5, 300)


def replay_journal_max_entries() -> int:
    return _bounded_int(
        "SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES",
        10000,
        256,
        10000,
    )


def replay_journal_max_bytes() -> int:
    return _bounded_int(
        "SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES",
        16 * 1024 * 1024,
        1024 * 1024,
        16 * 1024 * 1024,
    )


def replay_journal_lock_timeout_ms() -> int:
    return _bounded_int(
        "SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS",
        2000,
        50,
        2000,
    )


def replay_journal_path() -> Path:
    return _absolute_file_path(
        os.environ.get(
            "SMART_ROUTER_NONCE_JOURNAL_PATH",
            "/var/lib/winsvpn-router/replay-nonces.sqlite3",
        ),
        "SMART_ROUTER_NONCE_JOURNAL_PATH",
    )


def _deadline_remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise ValueError("replay deadline is invalid")
    if not math.isfinite(deadline):
        raise ValueError("replay deadline is invalid")
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise _DeadlineExpired("replay deadline expired")
    return remaining


def _sqlite_timeout_seconds(timeout_ms: int, deadline: float | None) -> float:
    remaining = _deadline_remaining(deadline)
    if remaining is None:
        return timeout_ms / 1000.0
    return min(timeout_ms / 1000.0, remaining)


def _sqlite_busy_timeout_ms(timeout_ms: int, deadline: float | None) -> int:
    remaining = _deadline_remaining(deadline)
    if remaining is None:
        return timeout_ms
    return min(timeout_ms, max(0, int(remaining * 1000)))


def replay_journal_ready(deadline: float | None = None) -> None:
    """Preinitialize or validate the replay journal without inserting a nonce.

    A missing or empty file becomes ready only after a schema-only
    initialization commits. An existing journal gets a rollback-only metadata
    write probe, so read-only or full-like storage cannot report ready and no
    unauthenticated nonce is left behind. An optional absolute monotonic
    deadline bounds the readiness probe.
    """
    path = replay_journal_path()
    maximum_bytes = replay_journal_max_bytes()
    timeout_ms = replay_journal_lock_timeout_ms()
    _validate_private_ancestors(path, "nonce journal")
    connection: sqlite3.Connection | None = None
    try:
        _deadline_remaining(deadline)
        try:
            before = _validate_private_regular_file(path, maximum_bytes, "nonce journal")
        except FileNotFoundError:
            before = _create_private_regular_file(path, maximum_bytes, "nonce journal")
        _deadline_remaining(deadline)
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=rw",
            timeout=_sqlite_timeout_seconds(timeout_ms, deadline),
            isolation_level=None,
            uri=True,
        )
        after = _validate_private_regular_file(path, maximum_bytes, "nonce journal")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RuntimeError("nonce journal was replaced while opening")
        DurableReplayGuard._configure_connection(
            connection,
            timeout_ms,
            maximum_bytes,
            deadline,
        )
        _deadline_remaining(deadline)
        connection.execute("BEGIN IMMEDIATE")
        initialized = DurableReplayGuard._initialize_or_validate(connection)
        _deadline_remaining(deadline)
        if initialized:
            connection.commit()
        else:
            connection.execute(
                "UPDATE replay_state SET wall_clock_high_water = "
                "wall_clock_high_water WHERE singleton = 1"
            )
            _deadline_remaining(deadline)
            connection.rollback()
    except (OSError, RuntimeError, sqlite3.Error, ValueError, OverflowError) as err:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
        if isinstance(err, _DeadlineExpired):
            raise
        if isinstance(err, RuntimeError):
            raise
        raise RuntimeError("nonce journal readiness validation failed") from err
    finally:
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                pass


def decision_log_max_file_bytes() -> int:
    return _bounded_int(
        "SMART_ROUTER_DECISION_LOG_MAX_FILE_BYTES",
        8 * 1024 * 1024,
        4096,
        64 * 1024 * 1024,
    )


def decision_log_max_files() -> int:
    return _bounded_int("SMART_ROUTER_DECISION_LOG_MAX_FILES", 4, 2, 16)


def decision_log_max_total_bytes() -> int:
    return _bounded_int(
        "SMART_ROUTER_DECISION_LOG_MAX_TOTAL_BYTES",
        16 * 1024 * 1024,
        8192,
        128 * 1024 * 1024,
    )


def decision_log_max_line_bytes() -> int:
    return min(65536, decision_log_max_file_bytes())


def decision_log_path() -> Path:
    # OI-12 (Round 36 treaty): the default leaves /tmp, which cannot satisfy
    # the private-ancestor checks this module enforces, for the systemd
    # StateDirectory the unit already provisions (winsvpn-router, mode 0700,
    # owned by the service user). DECISIONS_FILE still overrides.
    return _absolute_file_path(
        os.environ.get("DECISIONS_FILE", "/var/lib/winsvpn-router/decisions.jsonl"),
        "DECISIONS_FILE",
    )


def _absolute_file_path(raw: str, name: str) -> Path:
    if not raw or "\x00" in raw:
        raise RuntimeError(f"{name} is invalid")
    path = Path(raw)
    if not path.is_absolute() or str(path) != raw or path.name in {"", ".", ".."}:
        raise RuntimeError(f"{name} must be a normalized absolute file path")
    return path


def _nofollow_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeError("O_NOFOLLOW is required")
    return nofollow | getattr(os, "O_CLOEXEC", 0)


def _validate_private_ancestors(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"{label} ancestor is not a real directory")
    parent_info = os.lstat(path.parent)
    if parent_info.st_uid != os.geteuid():
        raise RuntimeError(f"{label} directory has the wrong owner")
    if stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise RuntimeError(f"{label} directory permissions must be 0700")


def _validate_private_regular_file(
    path: Path,
    maximum_bytes: int,
    label: str,
    *,
    enforce_size: bool = True,
) -> os.stat_result:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} is not a regular file")
    if info.st_nlink != 1:
        raise RuntimeError(f"{label} must not have hard links")
    if info.st_uid != os.geteuid():
        raise RuntimeError(f"{label} has the wrong owner")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError(f"{label} permissions must be 0600")
    if enforce_size and info.st_size > maximum_bytes:
        raise RuntimeError(f"{label} exceeds its configured size bound")
    return info


def _create_private_regular_file(
    path: Path,
    maximum_bytes: int,
    label: str,
) -> os.stat_result:
    _validate_private_ancestors(path, label)
    try:
        return _validate_private_regular_file(path, maximum_bytes, label)
    except FileNotFoundError:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _nofollow_flags()
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return _validate_private_regular_file(path, maximum_bytes, label)
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return _validate_private_regular_file(path, maximum_bytes, label)


def _fsync_parent(path: Path) -> None:
    flags = os.O_RDONLY | _nofollow_flags()
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory:
        flags |= directory
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise RuntimeError("bounded file write returned no bytes")
        offset += written


def parse_decision_log_line(raw: bytes, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("decision log line must be bytes")
    if len(raw) > maximum_bytes:
        raise ValueError("decision log line exceeds bound")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw:
        raise ValueError("decision log line is empty")
    if b"\n" in raw or b"\r" in raw:
        raise ValueError("decision log line contains a newline")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as err:
        raise ValueError("decision log line must be ASCII") from err
    decoder = json.JSONDecoder()
    try:
        record, index = decoder.raw_decode(text)
    except json.JSONDecodeError as err:
        raise ValueError("decision log line is not valid JSON") from err
    if index != len(text):
        raise ValueError("decision log line has trailing data")
    if not isinstance(record, dict):
        raise ValueError("decision log line must be an object")
    return record


def encode_decision_record(record: dict[str, Any], maximum_bytes: int) -> bytes:
    if not isinstance(record, dict):
        raise RuntimeError("decision record must be an object")
    payload = (
        json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        + "\n"
    ).encode("ascii")
    if len(payload) > maximum_bytes:
        raise RuntimeError("decision record exceeds its configured size bound")
    parsed = parse_decision_log_line(payload, maximum_bytes)
    if not isinstance(parsed, dict):
        raise RuntimeError("decision record round-trip failed")
    return payload


def auth_secret() -> str:
    secret = (
        os.environ.get("SMART_ROUTER_HMAC_SECRET", "").strip()
        or os.environ.get("EDGE_ROUTER_SECRET", "").strip()
    )
    if len(secret) < 32:
        raise RuntimeError(
            "SMART_ROUTER_HMAC_SECRET or EDGE_ROUTER_SECRET must contain at least 32 characters"
        )
    return secret


def signing_message(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    query: str | bytes = "",
) -> bytes:
    query_bytes = (
        bytes(query)
        if isinstance(query, (bytes, bytearray))
        else (query or "").encode("ascii")
    )
    target = path.encode("ascii") + (b"?" + query_bytes if query_bytes else b"")
    body_hash = hashlib.sha256(body).hexdigest().encode("ascii")
    return b"\n".join(
        (method.upper().encode("ascii"), target, timestamp.encode("ascii"),
         nonce.encode("ascii"), body_hash)
    )


def replay_retention_end(now: float, ttl: float, timestamp: float | None = None) -> float:
    """Return the last wall time a nonce must remain blocked.

    HMAC admission uses abs(now - signed_at) <= ttl, so a timestamp stays
    acceptable through signed_at + ttl inclusive, including a future-skewed
    signed_at of now + ttl. When the caller omits the signed timestamp, this
    assumes that maximum accepted future skew.
    """
    if not math.isfinite(now) or not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("replay retention window is invalid")
    if timestamp is None:
        signed_at = now + ttl
    else:
        if not math.isfinite(timestamp) or abs(now - timestamp) > ttl:
            raise ValueError("HMAC timestamp is outside the auth window")
        signed_at = timestamp
    end = signed_at + ttl
    if not math.isfinite(end) or end < now:
        raise ValueError("replay retention end is invalid")
    return end


def sign_request(
    secret: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    query: str | bytes = "",
) -> str:
    """Shared helper for the future production-hub client and offline tests."""
    return hmac.new(
        secret.encode("utf-8"),
        signing_message(method, path, timestamp, nonce, body, query=query),
        hashlib.sha256,
    ).hexdigest()


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float) -> bool:
        limit = _bounded_int("SMART_ROUTER_RATE_LIMIT_REQUESTS", 120, 1, 10000)
        window = _bounded_int("SMART_ROUTER_RATE_WINDOW_SECONDS", 60, 1, 3600)
        cutoff = now - window
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class ReplayDecision(Enum):
    ACCEPTED = "accepted"
    REPLAY = "replay"
    UNAVAILABLE = "unavailable"


class DurableReplayGuard:
    """SQLite nonce journal shared by every process serving this instance.

    A new connection and BEGIN IMMEDIATE transaction per authenticated request
    make unique nonce insertion atomic across threads, workers, and restarts.
    Retention strictly outlives every accepted HMAC timestamp, including the
    future-skew bound, so the same nonce stays blocked through both inclusive
    auth-window edges. Duplicate inserts surface as IntegrityError and become
    REPLAY. Capacity, storage, integrity, schema, lock, or permission errors
    return UNAVAILABLE; callers must fail closed rather than route the request.
    """

    @staticmethod
    def _validate_ancestors(path: Path) -> None:
        _validate_private_ancestors(path, "nonce journal")

    @staticmethod
    def _validate_file(path: Path, maximum_bytes: int) -> os.stat_result:
        return _validate_private_regular_file(path, maximum_bytes, "nonce journal")

    def _secure_file(self, path: Path, maximum_bytes: int) -> os.stat_result:
        return _create_private_regular_file(path, maximum_bytes, "nonce journal")

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()
        if version != (_REPLAY_SCHEMA_VERSION,):
            raise RuntimeError("nonce journal schema version mismatch")
        objects = connection.execute(
            "SELECT type, name FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        if objects != [("table", "replay_nonces"), ("table", "replay_state")]:
            raise RuntimeError("nonce journal schema objects mismatch")
        columns = connection.execute("PRAGMA table_info(replay_nonces)").fetchall()
        expected = [
            (0, "nonce_hash", "BLOB", 1, None, 1),
            (1, "accepted_at", "REAL", 1, None, 0),
            (2, "expires_at", "REAL", 1, None, 0),
        ]
        if columns != expected:
            raise RuntimeError("nonce journal table definition mismatch")
        definition = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
            ("replay_nonces",),
        ).fetchone()
        if definition != (_REPLAY_TABLE_SQL,):
            raise RuntimeError("nonce journal table definition mismatch")
        state_columns = connection.execute("PRAGMA table_info(replay_state)").fetchall()
        expected_state_columns = [
            (0, "singleton", "INTEGER", 1, None, 1),
            (1, "wall_clock_high_water", "REAL", 1, None, 0),
        ]
        if state_columns != expected_state_columns:
            raise RuntimeError("nonce journal state definition mismatch")
        state_definition = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
            ("replay_state",),
        ).fetchone()
        if state_definition != (_REPLAY_STATE_TABLE_SQL,):
            raise RuntimeError("nonce journal state definition mismatch")
        state = connection.execute(
            "SELECT singleton, wall_clock_high_water FROM replay_state"
        ).fetchall()
        if len(state) != 1 or state[0][0] != 1:
            raise RuntimeError("nonce journal wall-clock state is invalid")
        high_water = state[0][1]
        if (
            isinstance(high_water, bool)
            or not isinstance(high_water, (int, float))
            or not math.isfinite(float(high_water))
        ):
            raise RuntimeError("nonce journal wall-clock state is invalid")

    @staticmethod
    def _validate_existing(connection: sqlite3.Connection) -> None:
        DurableReplayGuard._validate_schema(connection)
        integrity = connection.execute("PRAGMA quick_check(1)").fetchone()
        if integrity != ("ok",):
            raise RuntimeError("nonce journal integrity check failed")

    @staticmethod
    def _configure_connection(
        connection: sqlite3.Connection,
        timeout_ms: int,
        maximum_bytes: int,
        deadline: float | None = None,
    ) -> None:
        effective_timeout_ms = _sqlite_busy_timeout_ms(timeout_ms, deadline)
        connection.execute(f"PRAGMA busy_timeout={effective_timeout_ms}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA synchronous=EXTRA")
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        if journal_mode != ("delete",):
            raise RuntimeError("nonce journal must use DELETE journaling")
        page_size = connection.execute("PRAGMA page_size").fetchone()
        if not page_size or not isinstance(page_size[0], int) or page_size[0] <= 0:
            raise RuntimeError("nonce journal page size is invalid")
        page_limit = maximum_bytes // page_size[0]
        if page_limit < 1:
            raise RuntimeError("nonce journal size bound is invalid")
        applied = connection.execute(f"PRAGMA max_page_count={page_limit}").fetchone()
        if not applied or applied[0] > page_limit:
            raise RuntimeError("nonce journal page bound was not applied")
        defensive = getattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE", None)
        if defensive is not None and hasattr(connection, "setconfig"):
            connection.setconfig(defensive, True)

    @staticmethod
    def _initialize_or_validate(connection: sqlite3.Connection) -> bool:
        version = connection.execute("PRAGMA user_version").fetchone()
        if version == (0,):
            existing = connection.execute(
                "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if existing:
                raise RuntimeError("unversioned nonce journal is not empty")
            connection.execute(_REPLAY_TABLE_SQL)
            connection.execute(_REPLAY_STATE_TABLE_SQL)
            connection.execute(
                "INSERT INTO replay_state(singleton, wall_clock_high_water) VALUES "
                "(1, ?)",
                (_REPLAY_INITIAL_HIGH_WATER,),
            )
            connection.execute(f"PRAGMA user_version={_REPLAY_SCHEMA_VERSION}")
            DurableReplayGuard._validate_existing(connection)
            return True
        DurableReplayGuard._validate_existing(connection)
        return False

    @staticmethod
    def _wall_clock_high_water(connection: sqlite3.Connection) -> float:
        state = connection.execute(
            "SELECT wall_clock_high_water FROM replay_state WHERE singleton = 1"
        ).fetchone()
        if state is None:
            raise RuntimeError("nonce journal wall-clock state is missing")
        high_water = state[0]
        if (
            isinstance(high_water, bool)
            or not isinstance(high_water, (int, float))
            or not math.isfinite(float(high_water))
        ):
            raise RuntimeError("nonce journal wall-clock state is invalid")
        return float(high_water)

    @staticmethod
    def _advance_wall_clock_high_water(
        connection: sqlite3.Connection,
        now: float,
    ) -> None:
        high_water = DurableReplayGuard._wall_clock_high_water(connection)
        if now < high_water:
            raise RuntimeError("nonce journal wall clock moved backwards")
        if now == high_water:
            return
        updated = connection.execute(
            "UPDATE replay_state SET wall_clock_high_water = ? "
            "WHERE singleton = 1",
            (now,),
        ).rowcount
        if updated != 1:
            raise RuntimeError("nonce journal wall-clock state update failed")

    def accept(
        self,
        nonce: str,
        now: float | None,
        ttl: float,
        timestamp: float | None = None,
        deadline: float | None = None,
    ) -> ReplayDecision:
        connection: sqlite3.Connection | None = None
        try:
            _deadline_remaining(deadline)
            path = replay_journal_path()
            maximum_entries = replay_journal_max_entries()
            maximum_bytes = replay_journal_max_bytes()
            timeout_ms = replay_journal_lock_timeout_ms()
            before = self._secure_file(path, maximum_bytes)
            _deadline_remaining(deadline)
            connection = sqlite3.connect(
                path,
                timeout=_sqlite_timeout_seconds(timeout_ms, deadline),
                isolation_level=None,
            )
            after = self._validate_file(path, maximum_bytes)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("nonce journal was replaced while opening")
            self._configure_connection(
                connection,
                timeout_ms,
                maximum_bytes,
                deadline,
            )
            _deadline_remaining(deadline)
            connection.execute("BEGIN IMMEDIATE")
            # Production samples wall time under the SQLite writer lock. A
            # request arrival sample can predate another worker's commit.
            if now is None:
                now = time.time()
                if timestamp is None or abs(now - timestamp) > ttl:
                    raise RuntimeError("request authentication window expired")
            expires_at = replay_retention_end(now, ttl, timestamp)
            self._initialize_or_validate(connection)

            _deadline_remaining(deadline)
            self._advance_wall_clock_high_water(connection, now)
            _deadline_remaining(deadline)
            connection.execute(
                "DELETE FROM replay_nonces WHERE expires_at < ?",
                (now,),
            )
            _deadline_remaining(deadline)
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).digest()
            try:
                connection.execute(
                    "INSERT INTO replay_nonces(nonce_hash, accepted_at, expires_at) "
                    "VALUES (?, ?, ?)",
                    (nonce_hash, now, expires_at),
                )
            except sqlite3.IntegrityError:
                _deadline_remaining(deadline)
                connection.rollback()
                return ReplayDecision.REPLAY
            _deadline_remaining(deadline)
            count = connection.execute("SELECT COUNT(*) FROM replay_nonces").fetchone()
            if count is None or count[0] > maximum_entries:
                connection.rollback()
                return ReplayDecision.UNAVAILABLE
            _deadline_remaining(deadline)
            connection.commit()
            _deadline_remaining(deadline)
            self._validate_file(path, maximum_bytes)
            return ReplayDecision.ACCEPTED
        except (OSError, RuntimeError, sqlite3.Error, ValueError, OverflowError):
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            return ReplayDecision.UNAVAILABLE
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass


class DurableDecisionLog:
    """Bounded JSONL decision log with descriptor-safe append and rotation.

    Writes use O_NOFOLLOW and O_APPEND, re-check the bound inode after open and
    after write, and refuse symlinks, hard links, and insecure modes. Rotation
    stays inside the same private directory. Routing callers must treat append
    failures as fail-closed for the log without weakening request admission.
    """

    _lock = threading.Lock()

    @staticmethod
    def _rotated_path(path: Path, index: int) -> Path:
        return path.with_name(f"{path.name}.{index}")

    def _unlink_private_file(self, path: Path, maximum_bytes: int) -> None:
        info = _validate_private_regular_file(
            path,
            maximum_bytes,
            "rotated decision log",
            enforce_size=False,
        )
        os.unlink(path)
        try:
            after = os.lstat(path)
        except FileNotFoundError:
            return
        if (after.st_dev, after.st_ino) == (info.st_dev, info.st_ino):
            raise RuntimeError("rotated decision log was not removed")

    def _rotate(self, path: Path, max_files: int, max_file_bytes: int) -> None:
        last = self._rotated_path(path, max_files - 1)
        try:
            os.lstat(last)
        except FileNotFoundError:
            pass
        else:
            self._unlink_private_file(last, max_file_bytes)
        for index in range(max_files - 2, 0, -1):
            source = self._rotated_path(path, index)
            destination = self._rotated_path(path, index + 1)
            try:
                before = _validate_private_regular_file(
                    source,
                    max_file_bytes,
                    "rotated decision log",
                )
            except FileNotFoundError:
                continue
            os.rename(source, destination)
            after = os.lstat(destination)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise RuntimeError("rotated decision log was replaced during rename")
        before = _validate_private_regular_file(path, max_file_bytes, "decision log")
        destination = self._rotated_path(path, 1)
        os.rename(path, destination)
        after = os.lstat(destination)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("decision log was replaced during rotation")
        _create_private_regular_file(path, max_file_bytes, "decision log")
        _fsync_parent(path)

    def _rotate_until_fits(
        self,
        path: Path,
        payload_len: int,
        max_file_bytes: int,
        max_files: int,
    ) -> None:
        _validate_private_ancestors(path, "decision log")
        try:
            info = _validate_private_regular_file(path, max_file_bytes, "decision log")
        except FileNotFoundError:
            _create_private_regular_file(path, max_file_bytes, "decision log")
            _fsync_parent(path)
            return
        if info.st_size + payload_len <= max_file_bytes:
            return
        if info.st_size == 0:
            raise RuntimeError("decision record exceeds its configured size bound")
        self._rotate(path, max_files, max_file_bytes)
        created = _validate_private_regular_file(path, max_file_bytes, "decision log")
        if created.st_size + payload_len > max_file_bytes:
            raise RuntimeError("decision record exceeds its configured size bound")

    def _open_append(self, path: Path, maximum_bytes: int) -> int:
        before = _create_private_regular_file(path, maximum_bytes, "decision log")
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | _nofollow_flags())
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise RuntimeError("decision log is not a regular file")
            if opened.st_nlink != 1:
                raise RuntimeError("decision log must not have hard links")
            if opened.st_uid != os.geteuid():
                raise RuntimeError("decision log has the wrong owner")
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise RuntimeError("decision log permissions must be 0600")
            if opened.st_size > maximum_bytes:
                raise RuntimeError("decision log exceeds its configured size bound")
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise RuntimeError("decision log was replaced while opening")
            named = os.lstat(path)
            if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
                raise RuntimeError("decision log is not a regular file")
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise RuntimeError("decision log was replaced while opening")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _append_locked(self, path: Path, payload: bytes, maximum_bytes: int) -> None:
        descriptor = self._open_append(path, maximum_bytes)
        try:
            opened = os.fstat(descriptor)
            if opened.st_size + len(payload) > maximum_bytes:
                raise RuntimeError("decision log exceeds its configured size bound")
            named = os.lstat(path)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise RuntimeError("decision log was replaced while opening")
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            written = os.fstat(descriptor)
            after = os.lstat(path)
            if (written.st_dev, written.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("decision log path was replaced after write")
            if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode):
                raise RuntimeError("decision log is not a regular file")
            if written.st_size > maximum_bytes:
                raise RuntimeError("decision log exceeds its configured size bound")
        finally:
            os.close(descriptor)

    def _log_members(
        self,
        path: Path,
        max_files: int,
        max_file_bytes: int,
    ) -> list[tuple[int, Path, int]]:
        members: list[tuple[int, Path, int]] = []
        for index in range(max_files):
            candidate = path if index == 0 else self._rotated_path(path, index)
            try:
                info = _validate_private_regular_file(
                    candidate,
                    max_file_bytes,
                    "decision log" if index == 0 else "rotated decision log",
                )
            except FileNotFoundError:
                continue
            members.append((index, candidate, info.st_size))
        return members

    def _enforce_total_bytes(
        self,
        path: Path,
        max_files: int,
        max_file_bytes: int,
        max_total_bytes: int,
    ) -> None:
        members = self._log_members(path, max_files, max_file_bytes)
        total = sum(size for _index, _member, size in members)
        while total > max_total_bytes:
            rotated = [item for item in members if item[0] > 0]
            if not rotated:
                break
            index, victim, size = max(rotated, key=lambda item: item[0])
            self._unlink_private_file(victim, max_file_bytes)
            total -= size
            members = [item for item in members if item[0] != index]
        if total > max_total_bytes:
            raise RuntimeError("decision log exceeds its configured total size bound")

    def append(self, record: dict[str, Any]) -> None:
        max_file_bytes = decision_log_max_file_bytes()
        max_files = decision_log_max_files()
        max_total_bytes = decision_log_max_total_bytes()
        if max_total_bytes < max_file_bytes:
            raise RuntimeError("decision log total byte bound is below the per-file bound")
        payload = encode_decision_record(record, decision_log_max_line_bytes())
        path = decision_log_path()
        with self._lock:
            self._rotate_until_fits(
                path,
                len(payload),
                max_file_bytes,
                max_files,
            )
            self._append_locked(path, payload, max_file_bytes)
            self._enforce_total_bytes(path, max_files, max_file_bytes, max_total_bytes)


RATE_LIMITER = SlidingWindowLimiter()
REPLAY_GUARD = DurableReplayGuard()
DECISION_LOG = DurableDecisionLog()


def reset_security_state() -> None:
    RATE_LIMITER.clear()


async def _reject(scope: dict, receive: Callable[[], Awaitable[dict]], send: Callable, status: int, detail: str) -> None:
    response = JSONResponse({"detail": detail}, status_code=status)
    await response(scope, receive, send)


async def _read_bounded_body(receive: Callable[[], Awaitable[dict]], limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return b"", True
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > limit:
            return b"", True
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks), False


class RouterSecurityMiddleware:
    """Bound body size, authenticate body bytes, rate-limit, then admit a nonce."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or scope.get("path") not in PROTECTED_PATHS:
            await self.app(scope, receive, send)
            return

        try:
            limit = max_body_bytes()
        except RuntimeError:
            await _reject(scope, receive, send, 503, "router security configuration invalid")
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > limit:
                    await _reject(scope, receive, send, 413, "request body too large")
                    return
            except ValueError:
                await _reject(scope, receive, send, 400, "invalid content length")
                return

        body, exceeded = await _read_bounded_body(receive, limit)
        if exceeded:
            await _reject(scope, receive, send, 413, "request body too large")
            return

        timestamp_raw = headers.get(b"x-smart-router-timestamp", b"").decode("ascii", "ignore")
        nonce = headers.get(b"x-smart-router-nonce", b"").decode("ascii", "ignore")
        supplied = headers.get(b"x-smart-router-signature", b"").decode("ascii", "ignore")
        try:
            secret = auth_secret()
            window = auth_window_seconds()
        except RuntimeError:
            await _reject(scope, receive, send, 503, "router authentication unavailable")
            return
        try:
            timestamp = int(timestamp_raw)
        except ValueError:
            await _reject(scope, receive, send, 401, "authentication required")
            return

        now_wall = time.time()
        if (
            not _NONCE_RE.fullmatch(nonce)
            or not _SIGNATURE_RE.fullmatch(supplied)
            or abs(now_wall - timestamp) > window
        ):
            await _reject(scope, receive, send, 401, "authentication required")
            return
        query = scope.get("query_string", b"")
        expected = sign_request(
            secret,
            scope.get("method", "GET"),
            scope.get("path", "/"),
            timestamp_raw,
            nonce,
            body,
            query=query,
        )
        if not hmac.compare_digest(supplied, expected):
            await _reject(scope, receive, send, 401, "authentication required")
            return

        client = scope.get("client") or ("unknown", 0)
        rate_key = str(client[0])
        try:
            allowed = RATE_LIMITER.allow(rate_key, time.monotonic())
        except RuntimeError:
            await _reject(scope, receive, send, 503, "router security configuration invalid")
            return
        if not allowed:
            await _reject(scope, receive, send, 429, "rate limit exceeded")
            return

        replay_decision = REPLAY_GUARD.accept(
            nonce,
            None,
            float(window),
            float(timestamp),
        )
        if replay_decision is ReplayDecision.REPLAY:
            await _reject(scope, receive, send, 401, "replayed request")
            return
        if replay_decision is not ReplayDecision.ACCEPTED:
            await _reject(scope, receive, send, 503, "replay protection unavailable")
            return

        sent = False

        async def replay_receive() -> dict:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)
