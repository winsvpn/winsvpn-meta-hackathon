"""EXT-37/38: protect pre-existing placement data and signal no process."""
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_host_location as probe


def test_existing_candidate_is_preserved(tmp_path):
    source = tmp_path / "host"
    source.write_bytes(b"new")
    candidate = tmp_path / "installed"
    candidate.mkdir()
    (candidate / "host").write_bytes(b"installed")
    (candidate / "sentinel").write_bytes(b"unrelated")
    with pytest.raises(FileExistsError):
        probe.place_host(source, str(candidate))
    assert (candidate / "host").read_bytes() == b"installed"
    assert (candidate / "sentinel").read_bytes() == b"unrelated"


def test_preexisting_probe_ancestor_survives(tmp_path):
    source = tmp_path / "host"
    source.write_bytes(b"fixture")
    ancestor = tmp_path / "wv-host-location-probe"
    ancestor.mkdir()
    sentinel = ancestor / "sentinel"
    sentinel.write_bytes(b"keep")
    target, created = probe.place_host(source, str(ancestor / "fresh" / "nested"))
    assert target.read_bytes() == b"fixture"
    probe.remove_placed(created)
    assert sentinel.read_bytes() == b"keep"
    assert not (ancestor / "fresh").exists()


def test_fresh_app_chain_removed_only_to_created_root(tmp_path):
    source = tmp_path / "host"
    source.write_bytes(b"fixture")
    _, created = probe.place_host(source, str(tmp_path / "Applications" / "WV Host Location Probe.app" / "Contents" / "Resources"))
    assert created == tmp_path / "Applications"
    probe.remove_placed(created)
    assert not created.exists()
    assert source.read_bytes() == b"fixture"
    target, created = probe.place_host(source, str(tmp_path))
    assert target == source and created is None
    probe.remove_placed(created)
    assert source.read_bytes() == b"fixture"


def test_survivors_are_reported_without_signals(tmp_path, monkeypatch):
    source = tmp_path / "host"
    watch = probe.ProcessWatch(source)
    def no_signal(*args):
        raise AssertionError("process must never be signalled")
    monkeypatch.setattr(probe.os, "kill", no_signal)
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=f"123 {source}\n"))
    assert watch.lingering() == [f"123 {source}"]
    assert not hasattr(watch, "kill_lingering")

