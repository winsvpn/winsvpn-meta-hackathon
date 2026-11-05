"""Private source fixture for Python gateway tests, without sourcing all DP."""
import atexit
import importlib.util
from pathlib import Path
import sys
import tempfile


def gateway_source(path, legacy=False):
    path = Path(path)
    if "# --- begin winn3 gateway block ---" not in path.read_text(encoding="utf-8"):
        return path
    tools = Path(__file__).resolve().parents[1] / "tools"
    sys.path.insert(0, str(tools))
    try:
        spec = importlib.util.spec_from_file_location("winn3_test_source", tools / "winn3_gateway_test_source.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        text = module.fixture(path, legacy)
    finally:
        sys.path.pop(0)
    directory = tempfile.TemporaryDirectory(prefix="winn3-dp-python-")
    atexit.register(directory.cleanup)
    result = Path(directory.name) / "gateway.sh"
    result.write_text(text, encoding="utf-8")
    return result
