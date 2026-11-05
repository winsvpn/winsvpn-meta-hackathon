import asyncio
import errno
import os
import stat
import sys
import threading
import types
from pathlib import Path

import pytest

if "httpx2" not in sys.modules:
    import httpx as _base_httpx

    _httpx2 = types.ModuleType("httpx2")
    for _k, _v in _base_httpx.__dict__.items():
        setattr(_httpx2, _k, _v)
    sys.modules["httpx2"] = _httpx2

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import security
import main
from security import DurableDecisionLog, parse_decision_log_line


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    directory = tmp_path / "decision-log"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "decisions.jsonl"
    monkeypatch.setenv("DECISIONS_FILE", str(path))
    monkeypatch.setenv("SMART_ROUTER_DECISION_LOG_MAX_FILE_BYTES", "4096")
    monkeypatch.setenv("SMART_ROUTER_DECISION_LOG_MAX_FILES", "3")
    monkeypatch.setenv("SMART_ROUTER_DECISION_LOG_MAX_TOTAL_BYTES", "8192")
    return path


def _record(index: int, pad: int = 0) -> dict:
    return {"n": index, "pad": "x" * pad}


def test_parser_rejects_malformed_or_oversized_lines():
    assert parse_decision_log_line(b'{"ok":true}\n', 1024) == {"ok": True}
    with pytest.raises(ValueError):
        parse_decision_log_line(b"", 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b"\n", 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b"[1]\n", 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b"null\n", 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'"string"\n', 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'{"ok":true}', 8)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'{"ok":true}{"x":1}\n', 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'{"ok":true}\n{"x":1}\n', 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'{"ok": true', 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'{"ok":true} \n', 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line(b'{"ok":true}\r\n', 1024)
    with pytest.raises(ValueError):
        parse_decision_log_line("{\"ok\":true}\n".encode("utf-16"), 1024)


def test_append_creates_private_file_and_round_trips(log_path):
    DurableDecisionLog().append(_record(1))
    info = os.lstat(log_path)
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_nlink == 1
    raw = log_path.read_bytes()
    assert parse_decision_log_line(raw, 4096)["n"] == 1


def test_rotation_keeps_file_count_and_byte_bounds(log_path):
    log = DurableDecisionLog()
    for index in range(12):
        log.append(_record(index, pad=700))
    current = log_path.read_bytes()
    assert current
    rotated = log_path.with_name(f"{log_path.name}.1")
    assert rotated.is_file()
    members = []
    total = 0
    for index, path in enumerate((log_path, rotated, log_path.with_name(f"{log_path.name}.2"))):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_size <= 4096
        members.append(index)
        total += info.st_size
    assert 0 in members
    assert 1 in members
    assert total <= 8192
    assert not log_path.with_name(f"{log_path.name}.3").exists()
    for path in (log_path, rotated, log_path.with_name(f"{log_path.name}.2")):
        if not path.is_file():
            continue
        for line in path.read_bytes().split(b"\n"):
            if not line:
                continue
            parse_decision_log_line(line + b"\n", 4096)


def test_symlink_path_replacement_does_not_write_through(log_path, tmp_path):
    victim = log_path.parent / "victim.txt"
    victim.write_bytes(b"untouched-secret")
    victim.chmod(0o600)
    log = DurableDecisionLog()
    log.append(_record(1))
    log_path.unlink()
    log_path.symlink_to(victim)
    with pytest.raises(RuntimeError):
        log.append(_record(2))
    assert victim.read_bytes() == b"untouched-secret"
    assert log_path.is_symlink()


def test_hardlink_and_insecure_mode_fail_closed(log_path):
    log = DurableDecisionLog()
    log.append(_record(1))
    second = log_path.with_name("second-link.jsonl")
    os.link(log_path, second)
    with pytest.raises(RuntimeError, match="hard links"):
        log.append(_record(2))
    second.unlink()
    log_path.chmod(0o644)
    with pytest.raises(RuntimeError, match="permissions"):
        log.append(_record(3))


def test_symlinked_parent_fails_closed(log_path, tmp_path, monkeypatch):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    real_parent.chmod(0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    monkeypatch.setenv("DECISIONS_FILE", str(linked_parent / "decisions.jsonl"))
    with pytest.raises(RuntimeError, match="ancestor"):
        DurableDecisionLog().append(_record(1))


def test_relative_or_replaced_path_fails_closed(log_path, monkeypatch):
    monkeypatch.setenv("DECISIONS_FILE", "relative-decisions.jsonl")
    with pytest.raises(RuntimeError, match="absolute"):
        DurableDecisionLog().append(_record(1))
    monkeypatch.setenv("DECISIONS_FILE", str(log_path))
    DurableDecisionLog().append(_record(1))
    outside = log_path.parent.parent / "outside.jsonl"
    log_path.unlink()
    log_path.symlink_to(outside)
    with pytest.raises(RuntimeError):
        DurableDecisionLog().append(_record(2))
    assert not outside.exists()


def test_disk_failure_fails_closed_and_leaves_log_unextended(log_path, monkeypatch):
    log = DurableDecisionLog()
    log.append(_record(1))
    before = log_path.read_bytes()

    def full(_descriptor, _payload):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(security.os, "write", full)
    with pytest.raises(OSError):
        log.append(_record(2))
    assert log_path.read_bytes() == before


def test_stale_handle_after_path_replacement_fails_closed(log_path, monkeypatch):
    victim = log_path.parent / "victim.txt"
    victim.write_bytes(b"untouched-secret")
    victim.chmod(0o600)
    log = DurableDecisionLog()
    log.append(_record(1))
    original_write = os.write

    def replace_then_write(descriptor, payload):
        log_path.unlink()
        log_path.symlink_to(victim)
        return original_write(descriptor, payload)

    monkeypatch.setattr(security.os, "write", replace_then_write)
    with pytest.raises(RuntimeError, match="replaced"):
        log.append(_record(2))
    assert victim.read_bytes() == b"untouched-secret"
    assert log_path.is_symlink()


def test_rotation_refuses_symlink_in_rotated_slot(log_path):
    log = DurableDecisionLog()
    for index in range(6):
        log.append(_record(index, pad=700))
    rotated = log_path.with_name(f"{log_path.name}.1")
    assert rotated.is_file()
    rotated.unlink()
    victim = log_path.parent / "rotate-victim.txt"
    victim.write_bytes(b"untouched-secret")
    victim.chmod(0o600)
    rotated.symlink_to(victim)
    with pytest.raises(RuntimeError):
        log.append(_record(99, pad=700))
    assert victim.read_bytes() == b"untouched-secret"


def test_concurrent_appends_stay_within_bounds(log_path):
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        barrier.wait(timeout=10)
        try:
            DurableDecisionLog().append(_record(index, pad=200))
        except BaseException as err:
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert errors == []
    total = 0
    files = 0
    for index in range(4):
        candidate = log_path if index == 0 else log_path.with_name(f"{log_path.name}.{index}")
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_size <= 4096
        total += info.st_size
        files += 1
        for line in candidate.read_bytes().split(b"\n"):
            if line:
                parse_decision_log_line(line + b"\n", 4096)
    assert files <= 3
    assert total <= 8192


def test_storage_offload_deadline_does_not_block_event_loop():
    entered = threading.Event()
    release = threading.Event()

    def stalled_storage():
        entered.set()
        release.wait(timeout=2)

    async def exercise():
        loop = asyncio.get_running_loop()
        started = loop.time()
        task = asyncio.create_task(
            main._run_storage_with_deadline(
                stalled_storage,
                deadline=started + 0.1,
            )
        )
        try:
            while not entered.is_set():
                assert loop.time() - started < 0.5
                await asyncio.sleep(0.001)
            heartbeat = loop.time()
            await asyncio.sleep(0.01)
            assert loop.time() - heartbeat < 0.1
            with pytest.raises(TimeoutError):
                await task
            assert loop.time() - started < 0.25
        finally:
            release.set()

    asyncio.run(exercise())


def test_storage_offload_cancellation_is_prompt_and_propagates():
    entered = threading.Event()
    release = threading.Event()

    def stalled_storage():
        entered.set()
        release.wait(timeout=2)

    async def exercise():
        loop = asyncio.get_running_loop()
        task = asyncio.create_task(
            main._run_storage_with_deadline(
                stalled_storage,
                deadline=loop.time() + 5,
            )
        )
        try:
            started = loop.time()
            while not entered.is_set():
                assert loop.time() - started < 0.5
                await asyncio.sleep(0.001)
            cancelled_at = loop.time()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert loop.time() - cancelled_at < 0.1
        finally:
            release.set()

    asyncio.run(exercise())


def test_storage_offload_refuses_unbounded_abandoned_worker_queue():
    entered = [threading.Event() for _ in range(main._STORAGE_MAX_WORKERS)]
    release = threading.Event()

    def stalled_storage(index):
        entered[index].set()
        release.wait(timeout=2)

    async def exercise():
        loop = asyncio.get_running_loop()
        tasks = [
            asyncio.create_task(
                main._run_storage_with_deadline(
                    stalled_storage,
                    index,
                    deadline=loop.time() + 1.5,
                )
            )
            for index in range(main._STORAGE_MAX_WORKERS)
        ]
        try:
            started = loop.time()
            while not all(item.is_set() for item in entered):
                assert loop.time() - started < 0.5
                await asyncio.sleep(0.001)
            refused_at = loop.time()
            with pytest.raises(TimeoutError, match="capacity exhausted"):
                await main._run_storage_with_deadline(
                    lambda: None,
                    deadline=loop.time() + 1.0,
                )
            assert loop.time() - refused_at < 0.1
        finally:
            release.set()
            await asyncio.gather(*tasks)

    asyncio.run(exercise())
