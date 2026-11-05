"""Finite successful-write bookkeeping checks on the private fixed source."""
import pytest
from test_controller_lifecycle import _run_node

@pytest.mark.parametrize("nonempty", [False, True])
def test_successful_block_write_facts_precede_postcheck(tmp_path, nonempty):
    got = _run_node(tmp_path, """
const {controller} = fixture();
const rules = NONEMPTY ? [{id: 1, priority: 1, action: {type: 'block'},
  condition: {urlFilter: 'example.test', resourceTypes: ['main_frame']}}] : [];
const expectedKey = JSON.stringify(rules.map(r => [r.id, r.priority, r.action.type,
  r.condition.urlFilter, [...r.condition.resourceTypes].sort()]));
const oldLayer = {ok: false, error: 'prior unavailability', dropped: []};
controller.applied.blockKey = 'previous';
controller.blockLayer = oldLayer;
controller.enforcementChanged = false;
controller.lastError = 'could not install the block rules: prior unavailability';
let completed = false;
let checks = 0;
controller.adapter.blockTypesDropped = ['font'];
controller.adapter.setBlockRules = async received => {
  assert.deepEqual(received, rules);
  await Promise.resolve();
  completed = true;
};
const ordinaryCheck = controller.assertReconcileGeneration.bind(controller);
controller.assertReconcileGeneration = generation => {
  ordinaryCheck(generation);
  checks++;
  if (checks === 1) {
    assert.equal(completed, false);
    assert.equal(controller.applied.blockKey, 'previous');
  } else {
    assert.equal(completed, true);
    assert.equal(controller.applied.blockKey, expectedKey);
    if (NONEMPTY) {
      assert.deepEqual(controller.blockLayer, {ok: true, error: '', dropped: ['font']});
      assert.equal(controller.enforcementChanged, true);
      assert.equal(controller.lastError, '');
    } else {
      assert.equal(controller.blockLayer, oldLayer);
      assert.equal(controller.enforcementChanged, false);
      assert.match(controller.lastError, /^could not install the block rules:/);
    }
  }
};
await controller.applyBlockRules(rules, controller.reconcileGeneration);
assert.equal(checks, 2);
console.log(JSON.stringify({checks, completed}));
""".replace("NONEMPTY", "true" if nonempty else "false"))
    assert got == {"checks": 2, "completed": True}

def test_ordinary_block_write_rejection_keeps_failure_bookkeeping(tmp_path):
    got = _run_node(tmp_path, """
const {controller} = fixture();
const failure = new Error('ordinary fixture adapter failure');
let invalidated = 0;
controller.applied.blockKey = 'previous';
controller.enforcementChanged = false;
controller.adapter.setBlockRules = async () => { throw failure; };
controller.adapter.invalidateBlockLayerTypes = () => { invalidated++; };
await assert.rejects(controller.applyBlockRules([], controller.reconcileGeneration),
  error => error === failure);
assert.equal(controller.applied.blockKey, null);
assert.equal(controller.blockLayer.ok, false);
assert.equal(controller.enforcementChanged, true);
assert.equal(invalidated, 1);
assert.match(controller.lastError, /^could not install the block rules:/);
console.log(JSON.stringify({invalidated, failed: true}));
""")
    assert got == {"invalidated": 1, "failed": True}
