"""EXT-16: the specified 200-rule, 200-URL, 100-iteration PAC benchmark."""
from pathlib import Path
import json
import shutil
import subprocess

import pytest

EXT = Path(__file__).resolve().parents[1]


def test_pac_match_benchmark():
    node = shutil.which('node')
    if node is None:
        pytest.skip('local Node runtime absent')
    source = (EXT / 'src/core/pac.js').read_text()
    start = source.index('function wvMatch(')
    end = source.index('function FindProxyForURL(', start)
    matchers = source[start:end]
    script = matchers + r'''
const rules = Array.from({ length: 200 }, (_, i) => `site${i}.example`);
const urls = Array.from({ length: 200 }, (_, i) => `https://sub.site${i}.example/path`);
const hosts = urls.map((url) => new URL(url).hostname);
let hits = 0;
const start = process.hrtime.bigint();
for (let iteration = 0; iteration < 100; iteration++) {
  for (const host of hosts) if (wvAny(rules, host)) hits++;
}
console.log(JSON.stringify({ hits, elapsedMs: Number(process.hrtime.bigint() - start) / 1e6 }));
'''
    result = subprocess.run([node, '--eval', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    measured = json.loads(result.stdout)
    assert measured['hits'] == 20000
    print(json.dumps(measured))
