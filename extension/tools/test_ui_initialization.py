"""EXT-13: failure responses cannot leave either UI able to mutate stale state."""
from pathlib import Path
import json
import shutil
import subprocess

import pytest

EXT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name('ui_initialization_fixture.js')


def sources():
    result = {name: (EXT / f'src/core/{name}.js').read_text() for name in ['constants', 'rules', 'copy']}
    locale = EXT / 'src/core/locale.js'
    result['locale'] = locale.read_text() if locale.exists() else ''
    result.update({name: (EXT / f'src/ui/{name}.js').read_text() for name in ['popup', 'options']})
    return result


@pytest.mark.parametrize('page', ['popup', 'options'])
@pytest.mark.parametrize('scenario', ['resolved', 'rejection', 'malformed', 'mutation', 'stale', 'recovery'])
def test_initialization_failure(page, scenario):
    node = shutil.which('node')
    if node is None:
        pytest.skip('local Node runtime absent')
    script = FIXTURE.read_text() + '\ncheckUiInitialization(' + json.dumps(sources()) + ',' + json.dumps(page) + ',' + json.dumps(scenario) + ').then(v => console.log(JSON.stringify(v))).catch(e => { console.error(e); process.exitCode = 1; });'
    result = subprocess.run([node, '--eval', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['passed']
