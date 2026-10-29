// Case 01: the full chain, end to end, and the one control that snaps it.
//
//   Vulnerable: a poisoned trouble report is read by the low-privilege intake
//     agent, promoted into a task, and dispatched. The orchestrator trusts the
//     task instead of the caller, the operator executes, and a hardship meter
//     goes dark. Four named links, one blackout.
//   Fixed: the same report, the same promoted task, the same low-privilege
//     caller. The orchestrator derives privilege from the caller, the disconnect
//     is above intake's grant, so it is refused and logged. The chain breaks at
//     the authorization link and the lights stay on.
//   Functionality: a real operator can still cut service when it is their call.

const { promote, PRIVILEGE } = require('./agents');
const { createOrchestrator: vulnerable } = require('./vulnerable/orchestrator');
const { createOrchestrator: fixed } = require('./fixed/orchestrator');

let passed = 0, failed = 0;
function report(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

const intake = { role: 'intake' };     // the agent that read the report: low privilege
const operator = { role: 'operator' }; // high privilege: allowed to cut service

console.log('== vulnerable orchestrator: the chain completes ==');
{
  const o = vulnerable();

  // link 1+2: intake reads the poisoned report, the directive is promoted to a task
  const text = o.world.meters.m_1.report;
  const task = promote(o.dispatch(intake, { action: 'readReport', meterId: 'm_1' }) || text);
  report('link 1-2: injected directive promotes to a disconnect task',
    task && task.action === 'issueDisconnect' && task.meterId === 'm_1', JSON.stringify(task));

  // link 3+4: the low-privilege caller's promoted task is dispatched and executed
  const cut = o.dispatch(intake, task);
  report('link 3-4: confused deputy executes the cut for a low-privilege caller',
    cut.ok === true && o.world.disconnects.length === 1, JSON.stringify(cut));

  // link 5: the hardship meter is dark
  report('link 5: malicious blackout, a hardship meter loses service',
    o.world.meters.m_1.hardship === true && o.world.meters.m_1.service === 'off',
    JSON.stringify(o.world.meters.m_1));
}

console.log('== fixed orchestrator: the chain breaks ==');
{
  const o = fixed();
  const text = o.world.meters.m_1.report;
  const task = promote(text); // injection still promotes: you cannot trust it away

  const denied = o.dispatch(intake, task); // same task, same low-privilege caller
  report('authz: the disconnect is refused for an intake-level caller',
    denied.ok === false && denied.code === 'PRIVILEGE', JSON.stringify(denied));
  report('the lights stay on: no disconnect executed, hardship meter still served',
    o.world.disconnects.length === 0 && o.world.meters.m_1.service === 'on',
    JSON.stringify(o.world.meters.m_1));
  report('the reach is logged, not swallowed',
    o.world.escalations.length === 1 && o.world.escalations[0].action === 'issueDisconnect',
    JSON.stringify(o.world.escalations));
}

console.log('== fixed orchestrator: real operations still work ==');
{
  const o = fixed();
  const cut = o.dispatch(operator, { action: 'issueDisconnect', meterId: 'm_1' });
  report('functionality: an authorized operator can still cut service',
    cut.ok === true && o.world.disconnects.length === 1, JSON.stringify(cut));
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
