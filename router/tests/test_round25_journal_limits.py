import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security


@pytest.mark.parametrize(
    "name,reader,maximum",
    [
        ("SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES", security.replay_journal_max_entries, 10000),
        ("SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES", security.replay_journal_max_bytes, 16777216),
        ("SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", security.replay_journal_lock_timeout_ms, 2000),
    ],
)
def test_policy_limit_is_a_ceiling(monkeypatch, name, reader, maximum):
    monkeypatch.setenv(name, str(maximum))
    assert reader() == maximum
    monkeypatch.setenv(name, str(maximum + 1))
    with pytest.raises(RuntimeError):
        reader()
