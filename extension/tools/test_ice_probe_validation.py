"""EXT-36: ICE capture errors cannot prove host-candidate suppression."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_chromium
import verify_firefox


@pytest.mark.parametrize("verifier", [verify_chromium, verify_firefox])
@pytest.mark.parametrize("raw", [None, "nope", "null", "{}", '"x"', '["ERROR boom"]', "[1]"])
def test_invalid_capture_is_refused(verifier, raw):
    with pytest.raises(RuntimeError):
        verifier._validated_ice_candidates(raw)


@pytest.mark.parametrize("verifier", [verify_chromium, verify_firefox])
def test_empty_end_marker_and_host_positive_control(verifier):
    assert verifier._validated_ice_candidates('[""]') == []
    assert verifier._validated_ice_candidates("[]") == []
    host = "candidate:1 1 UDP 1 192.0.2.1 1234 typ host"
    relay = "candidate:2 1 UDP 1 192.0.2.2 1234 typ relay"
    assert verifier._validated_ice_candidates(json.dumps([host])) == [host]
    assert verifier.has_host_ice_candidate([host])
    assert not verifier.has_host_ice_candidate([relay])
    assert not verifier.has_host_ice_candidate([])


def test_execution_error_is_refused():
    def fail(*args, **kwargs):
        raise OSError("capture failed")
    harness = SimpleNamespace(use_page=lambda: None, m=SimpleNamespace(execute_async=fail))
    with pytest.raises(RuntimeError, match="execution failed"):
        verify_firefox.gather_ice(harness)

